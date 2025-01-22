package caddywaf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func (m *Middleware) processRuleMatch(w http.ResponseWriter, r *http.Request, rule *Rule, value string, state *WAFState) bool {
	logID, _ := r.Context().Value("logID").(string)
	if logID == "" {
		logID = uuid.New().String()
	}

	m.logRequest(zapcore.DebugLevel, "Rule matched during evaluation", r,
		zap.String("rule_id", string(rule.ID)),
		zap.String("target", strings.Join(rule.Targets, ",")),
		zap.String("value", value),
		zap.String("description", rule.Description),
		zap.Int("score", rule.Score),
	)

	// Increment rule hit count
	if count, ok := m.ruleHits.Load(rule.ID); ok {
		newCount := count.(HitCount) + 1
		m.ruleHits.Store(rule.ID, newCount)
		m.logger.Debug("Incremented rule hit count",
			zap.String("rule_id", string(rule.ID)),
			zap.Int("new_count", int(newCount)),
		)
	} else {
		m.ruleHits.Store(rule.ID, HitCount(1))
		m.logger.Debug("Initialized rule hit count",
			zap.String("rule_id", string(rule.ID)),
			zap.Int("new_count", 1),
		)
	}

	// Increment rule hits by phase
	m.muMetrics.Lock()
	if m.ruleHitsByPhase == nil {
		m.ruleHitsByPhase = make(map[int]int64)
	}
	m.ruleHitsByPhase[rule.Phase]++
	m.muMetrics.Unlock()

	oldScore := state.TotalScore
	state.TotalScore += rule.Score
	m.logRequest(zapcore.DebugLevel, "Increased anomaly score", r,
		zap.String("log_id", logID),
		zap.String("rule_id", string(rule.ID)),
		zap.Int("score_increase", rule.Score),
		zap.Int("old_total_score", oldScore),
		zap.Int("new_total_score", state.TotalScore),
		zap.Int("anomaly_threshold", m.AnomalyThreshold),
	)

	shouldBlock := false
	blockReason := ""

	if !state.ResponseWritten {
		if state.TotalScore >= m.AnomalyThreshold {
			shouldBlock = true
			blockReason = "Anomaly threshold exceeded"
		} else if rule.Action == "block" {
			shouldBlock = true
			blockReason = "Rule action is 'block'"
		}
	}

	m.logger.Debug("Processing rule action",
		zap.String("rule_id", string(rule.ID)),
		zap.String("action", rule.Action),
		zap.Bool("should_block", shouldBlock),
		zap.String("block_reason", blockReason),
	)

	if shouldBlock && !state.ResponseWritten {
		m.blockRequest(w, r, state, http.StatusForbidden, blockReason, string(rule.ID), value,
			zap.Int("total_score", state.TotalScore),
			zap.Int("anomaly_threshold", m.AnomalyThreshold),
		)
		return false // Stop further processing
	}

	if rule.Action == "log" {
		m.logRequest(zapcore.InfoLevel, "Rule action is 'log', request allowed but logged", r,
			zap.String("log_id", logID),
			zap.String("rule_id", string(rule.ID)),
		)
	} else if !shouldBlock && !state.ResponseWritten {
		m.logRequest(zapcore.DebugLevel, "Rule matched, no blocking action taken", r,
			zap.String("log_id", logID),
			zap.String("rule_id", string(rule.ID)),
			zap.String("action", rule.Action),
			zap.Int("total_score", state.TotalScore),
			zap.Int("anomaly_threshold", m.AnomalyThreshold),
		)
	}

	return true // Continue processing
}

func validateRule(rule *Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule has an empty ID")
	}
	if rule.Pattern == "" {
		return fmt.Errorf("rule '%s' has an empty pattern", rule.ID)
	}
	if len(rule.Targets) == 0 {
		return fmt.Errorf("rule '%s' has no targets", rule.ID)
	}
	if rule.Phase < 1 || rule.Phase > 4 {
		return fmt.Errorf("rule '%s' has an invalid phase: %d. Valid phases are 1 to 4", rule.ID, rule.Phase)
	}
	if rule.Score < 0 {
		return fmt.Errorf("rule '%s' has a negative score", rule.ID)
	}
	if rule.Action != "" && rule.Action != "block" && rule.Action != "log" {
		return fmt.Errorf("rule '%s' has an invalid action: '%s'. Valid actions are 'block' or 'log'", rule.ID, rule.Action)
	}
	return nil
}

// loadRules updates the RuleCache when rules are loaded and sorts rules by priority.
func (m *Middleware) loadRules(paths []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Debug("Loading rules from files", zap.Strings("rule_files", paths))

	m.Rules = make(map[int][]Rule)
	totalRules := 0
	var invalidFiles []string
	var allInvalidRules []string
	ruleIDs := make(map[string]bool)

	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			m.logger.Error("Failed to read rule file", zap.String("file", path), zap.Error(err))
			invalidFiles = append(invalidFiles, path)
			continue
		}

		var rules []Rule
		if err := json.Unmarshal(content, &rules); err != nil {
			m.logger.Error("Failed to unmarshal rules from file", zap.String("file", path), zap.Error(err))
			invalidFiles = append(invalidFiles, path)
			continue
		}

		// Sort rules by priority (higher priority first)
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Priority > rules[j].Priority
		})

		var invalidRulesInFile []string
		for i, rule := range rules {
			if err := validateRule(&rule); err != nil {
				invalidRulesInFile = append(invalidRulesInFile, fmt.Sprintf("Rule at index %d: %v", i, err))
				continue
			}

			if _, exists := ruleIDs[string(rule.ID)]; exists {
				invalidRulesInFile = append(invalidRulesInFile, fmt.Sprintf("Duplicate rule ID '%s' at index %d", rule.ID, i))
				continue
			}
			ruleIDs[string(rule.ID)] = true

			// Check RuleCache first
			if regex, exists := m.ruleCache.Get(rule.ID); exists {
				rule.regex = regex
			} else {
				regex, err := regexp.Compile(rule.Pattern)
				if err != nil {
					m.logger.Error("Failed to compile regex for rule", zap.String("rule_id", string(rule.ID)), zap.String("pattern", rule.Pattern), zap.Error(err))
					invalidRulesInFile = append(invalidRulesInFile, fmt.Sprintf("Rule '%s': invalid regex pattern: %v", rule.ID, err))
					continue
				}
				rule.regex = regex
				m.ruleCache.Set(rule.ID, regex) // Cache the compiled regex
			}

			if _, ok := m.Rules[rule.Phase]; !ok {
				m.Rules[rule.Phase] = []Rule{}
			}

			m.Rules[rule.Phase] = append(m.Rules[rule.Phase], rule)
			totalRules++
		}
		if len(invalidRulesInFile) > 0 {
			m.logger.Warn("Some rules failed validation", zap.String("file", path), zap.Strings("invalid_rules", invalidRulesInFile))
			allInvalidRules = append(allInvalidRules, invalidRulesInFile...)
		}

		m.logger.Info("Rules loaded", zap.String("file", path), zap.Int("total_rules", len(rules)), zap.Int("invalid_rules", len(invalidRulesInFile)))
	}

	if len(invalidFiles) > 0 {
		m.logger.Warn("Some rule files could not be loaded", zap.Strings("invalid_files", invalidFiles))
	}
	if len(allInvalidRules) > 0 {
		m.logger.Warn("Some rules across files failed validation", zap.Strings("invalid_rules", allInvalidRules))
	}

	if totalRules == 0 && len(invalidFiles) > 0 {
		return fmt.Errorf("no valid rules were loaded from any file")
	}
	m.logger.Debug("Rules loaded successfully", zap.Int("total_rules", totalRules))

	return nil
}
