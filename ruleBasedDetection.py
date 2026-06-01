# Assignment: Rule-Based Network Intrusion Detection

# HOW TO TEST LOCALLY:
#   Run: python ruleBasedDetection.py
#   The built-in evaluator will score your rules against the dataset.


def detectAttack(row):
    """
    Classify a single network connection record as attack or normal.

    Parameters
    ----------
    row : dict
        A dictionary of feature name -> numeric value for one connection.

    Returns
    -------
    bool
        True  = predicted ATTACK
        False = predicted NORMAL
    """

    # ------------------------------------------------------------------
    # BASELINE RULE 1: High TTL with no response
    # Rationale: High source TTL packets that generate zero destination packets are characteristic of one-sided scan/probe traffic.
    # ------------------------------------------------------------------
    if row['sttl'] > 200 and row['dpkts'] == 0:
        return True

    # ------------------------------------------------------------------
    # BASELINE RULE 2: Extreme rate, near-zero duration
    # Rationale: Legitimate connections rarely transfer at extreme rates in sub-millisecond bursts; this pattern is typical of flood attacks.
    # ------------------------------------------------------------------
    if row['rate'] > 100000 and row['dur'] < 0.001:
        return True

    # ------------------------------------------------------------------
    # BASELINE RULE 3: High source load, zero destination load
    # Rationale: One-directional high-bandwidth flows with no return traffic are a strong signal of DoS or data exfiltration attacks.
    # ------------------------------------------------------------------
    if row['sload'] > 10000000 and row['dload'] == 0:
        return True

    # ------------------------------------------------------------------
    # BASELINE RULE 4: State-TTL pattern with no response
    # Rationale: ct_state_ttl == 2 combined with zero destination packets indicates a specific TTL anomaly pattern seen in attack traffic.
    # ------------------------------------------------------------------
    if row['ct_state_ttl'] == 2 and row['dpkts'] == 0:
        return True

    # ------------------------------------------------------------------
    # ADD YOUR EXTRA RULES BELOW THIS LINE
    # ------------------------------------------------------------------

    # YOUR RULE 5 HERE:
    # if row['FEATURE'] OPERATOR VALUE:
    #     return True

    # YOUR RULE 6 HERE:
    # if row['FEATURE'] OPERATOR VALUE:
    #     return True

    # YOUR RULE 7 HERE:
    # if row['FEATURE'] OPERATOR VALUE and row['FEATURE'] OPERATOR VALUE:
    #     return True

    # Add as many rules as you like...

    # ------------------------------------------------------------------
    # DEFAULT: No rule matched → classify as Normal
    # ------------------------------------------------------------------
    return False


# LOCAL EVALUATOR
def evaluateDetector(csvPath, detectorFn):
    """
    Evaluate a detector function against a labelled CSV dataset.

    Parameters
    ----------
    csvPath : str
        Path to a dataset.
    detectorFn : callable
        A function that takes a row dict.

    Returns
    -------
    dict with keys: accuracy, precision, recall, f1
    """
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    import csv
    with open(csvPath, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for rawRow in reader:
            # Convert all numeric-looking fields to float
            row = {}
            for k, v in rawRow.items():
                try:
                    row[k] = float(v)
                except (ValueError, TypeError):
                    row[k] = v

            actual = int(row['label']) == 1
            predicted = detectorFn(row)

            if predicted and actual:
                tp += 1
            elif predicted and not actual:
                fp += 1
            elif not predicted and actual:
                fn += 1
            else:
                tn += 1

    total = tp + fp + tn + fn
    accuracy  = (tp + tn) / total * 100 if total > 0 else 0
    precision = tp / (tp + fp) * 100   if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) * 100   if (tp + fn) > 0 else 0
    f1 = (2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0)

    return {
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'accuracy': round(accuracy, 2),
        'precision': round(precision, 2),
        'recall': round(recall, 2),
        'f1': round(f1, 2),
    }


if __name__ == '__main__':
    import os

    # Look for the dataset next to this file or in the current working directory
    candidates = [
        os.path.join(os.path.dirname(__file__), 'UNSW_NB15_balanced_30k.csv'),
        'UNSW_NB15_balanced_30k.csv',
    ]
    datasetPath = None
    for c in candidates:
        if os.path.exists(c):
            datasetPath = os.path.abspath(c)
            break

    if datasetPath is None:
        print("ERROR: Could not find UNSW_NB15_balanced_30k.csv")
        print("Place it in the same folder as this script and try again.")
        exit(1)

    print(f"Evaluating against: {datasetPath}\n")
    results = evaluateDetector(datasetPath, detectAttack)

    print("=" * 50)
    print("  YOUR RESULTS")
    print("=" * 50)
    print(f"  Accuracy  : {results['accuracy']:.1f}%")
    print(f"  Precision : {results['precision']:.1f}%")
    print(f"  Recall    : {results['recall']:.1f}%")
    print(f"  F1 Score  : {results['f1']:.1f}%")
    print("=" * 50)
    print(f"  TP={results['tp']}  FP={results['fp']}  TN={results['tn']}  FN={results['fn']}")
    print("=" * 50)
