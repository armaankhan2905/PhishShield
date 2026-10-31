# Accuracy Improvement Plan — PrivacyLens

## Current State
- Token accuracy: 67.8%
- Entity recall: 70.3%
- Target: 92% token accuracy

## Issues Found
1. Regex patterns don't handle formatted numbers (spaces, dashes)
2. Model needs more training data and better practices
3. Missing 9-digit number detection
4. Label alignment could be improved

## Improvement Strategy

### Phase 1: Fix Regex Layer (ArMan's slice)
- Handle card numbers with spaces/dashes
- Add 9-digit number detection
- Improve pattern coverage

### Phase 2: Improve Model Training (Samanyu)
- Better corpus with more variations
- Data augmentation
- Better training hyperparameters
- Use techniques from Anthropic/OpenAI docs

### Phase 3: Ensemble & Iterate
- Combine regex + model outputs
- Recursive improvement loop
- Target 92% accuracy
