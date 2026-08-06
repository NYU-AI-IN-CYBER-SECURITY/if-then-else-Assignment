# Rule-Based Network Intrusion Detection

**Course Assignment - Gradescope Submission**

---

## Overview

In this assignment you will build a rule-based intrusion detection system using the UNSW-NB15 network traffic dataset. Your goal is to write a set of `if/elif/else` rules that classify each network connection as either an **attack** or **normal** traffic.

This assignment is intentionally constraint-based. No machine learning, no statistics, no libraries. It's just your understanding of the data and the patterns you find in it. It is designed to give you hands-on experience reading a real network security dataset and translating observations into logic, which is exactly the kind of reasoning you will need when working with and evaluating more complex detection systems later in the course.

---

## The Dataset — UNSW-NB15

The UNSW-NB15 dataset was created by the Australian Centre for Cyber Security at the University of New South Wales. It contains real network packet captures mixed with synthetic attack traffic generated using the IXIA PerfectStorm tool, covering nine modern attack categories.

**Official dataset page:** https://research.unsw.edu.au/projects/unsw-nb15-dataset

**Citation:**
> Moustafa, N., & Slay, J. (2015). UNSW-NB15: a comprehensive data set for network intrusion detection systems. *2015 Military Communications and Information Systems Conference (MilCIS)*, IEEE.

### Your Training File

You are provided with **`UNSW_NB15_training_30k.csv`** in this repository which is a balanced subset of 30,000 connection records:

| Split | Count |
|-------|-------|
| Normal (`label = 0`) | 15,000 |
| Attack (`label = 1`) | 15,000 |
| **Total** | **30,000** |

Download it from the course LMS and place it in the same folder as `ruleBasedDetection.py` before testing locally.

> **Note:** The autograder runs your rules against a separate, unseen dataset of the same format. Writing rules that generalise beyond the training data will yield a better grade.

### Attack Categories in the Dataset

| Category | Description |
|---|---|
| Fuzzers | Sending random or semi-random data to find crashes or unexpected behaviour |
| Analysis | Port scans, spam, and HTML file infiltration |
| Backdoors | Secret bypass of normal authentication |
| DoS | Denial-of-service attacks aimed at exhausting target resources |
| Exploits | Attacks leveraging known software vulnerabilities |
| Generic | Attacks targeting block-cipher-based encryption |
| Reconnaissance | Information gathering — probing and scanning |
| Shellcode | Injecting and executing arbitrary shellcode |
| Worms | Self-replicating malware spreading across networks |

### Feature Reference

All features in the dataset are numeric. The `label` column is the ground truth. **Do not use it in your rules**.

| Feature | Description |
|---|---|
| `dur` | Duration of the connection (seconds) |
| `spkts` | Source-to-destination packet count |
| `dpkts` | Destination-to-source packet count |
| `sbytes` | Source-to-destination byte count |
| `dbytes` | Destination-to-source byte count |
| `rate` | Overall transfer rate (bps) |
| `sttl` | Source IP TTL value |
| `dttl` | Destination IP TTL value |
| `sload` | Source bits per second |
| `dload` | Destination bits per second |
| `sloss` | Source packet retransmission / drop count |
| `dloss` | Destination packet retransmission / drop count |
| `sinpkt` | Source inter-packet arrival time (ms) |
| `dinpkt` | Destination inter-packet arrival time (ms) |
| `sjit` | Source jitter (ms) |
| `djit` | Destination jitter (ms) |
| `swin` | Source TCP window advertisement size |
| `dwin` | Destination TCP window advertisement size |
| `smean` | Mean of source packet sizes (bytes) |
| `dmean` | Mean of destination packet sizes (bytes) |
| `trans_depth` | HTTP request/response pipeline depth |
| `response_body_len` | HTTP response body length (bytes) |
| `ct_srv_src` | Connections with same service and source address in last 100 |
| `ct_state_ttl` | Encoded combination of connection state and TTL values |
| `ct_dst_ltm` | Connections to same destination address in last 100 |
| `ct_src_dport_ltm` | Connections from same source address and destination port in last 100 |
| `ct_dst_sport_ltm` | Connections to same destination address and source port in last 100 |
| `ct_dst_src_ltm` | Connections between same source and destination in last 100 |
| `ct_src_ltm` | Connections from same source address in last 100 |
| `ct_srv_dst` | Connections to same service and destination address in last 100 |
| `is_ftp_login` | 1 if FTP session used username/password authentication |
| `ct_ftp_cmd` | Number of FTP commands in the session |
| `ct_flw_http_mthd` | Number of HTTP methods (GET, POST, etc.) in the transaction |
| `is_sm_ips_ports` | 1 if source and destination IP address and port are identical |
| `label` | Ground truth: 0 = Normal, 1 = Attack — **do not use in rules** |

---

## Your Task

Open `ruleBasedDetection.py`. You will find a function called `detectAttack(row)` with four pre-populated baseline rules. Your job is to **add more rules below the baseline** to improve the classification performance.

The function receives one connection record as a Python dictionary and must return:
- `True` if you believe the connection is an **attack**
- `False` if you believe it is **normal**

### Baseline Rules (already provided)

```python
# Rule 1: High TTL with no response
if row['sttl'] > 200 and row['dpkts'] == 0:
    return True

# Rule 2: Extreme rate, near-zero duration
if row['rate'] > 100000 and row['dur'] < 0.001:
    return True

# Rule 3: High source load, zero destination load
if row['sload'] > 10000000 and row['dload'] == 0:
    return True

# Rule 4: State-TTL pattern with no response
if row['ct_state_ttl'] == 2 and row['dpkts'] == 0:
    return True
```

### Writing Your Own Rules

Add your rules in the clearly marked section **below** the four baselines. Each rule is a single `if` statement that returns `True` for a predicted attack:

```python
# Example
if row['FEATURE'] > VALUE:
    return True
```

You can combine multiple conditions:

```python
if row['FEATURE1'] == VALUE1 and row['FEATURE2'] == VALUE2:
    return True
```

You can also use arithmetic inside conditions:

```python
if row['FEATURE1'] > row['FEATURE2'] * VALUE1 and row['FEATURE3'] > VALUE2:
    return True
```

There is no limit on how many rules you add.

---

## Rules and Constraints

These are enforced automatically by the autograder. Violations result in a score of **0**.

| Allowed | Not Allowed |
|---|---|
| `if / elif / else` | `import` statements of any kind |
| `==  !=  >  <  >=  <=` | Function calls (`abs()`, `len()`, `max()`, etc.) |
| `and  or  not` | List, set, or dictionary comprehensions |
| `+  -  *  /` inside conditions | Loops (`for`, `while`) |
| | Machine learning or statistics libraries |
| | Defining new functions or classes |

---

## Testing Locally

Run the file directly from your terminal:

```bash
python ruleBasedDetection.py
```

Make sure `UNSW_NB15_training_30k.csv` is in the same folder. 

**Test as often as you like.** Only your Gradescope submission counts for marks.

---

## Grading

Your submission is graded against a separate, unseen dataset of the same format. Your score is based on how much you improve each metric **relative to the four baseline rules**. Metrics that improve are rewarded; metrics that drop below the baseline are penalised.

You will see a per-metric breakdown on Gradescope after each submission so you can see exactly which metrics your rules are helping or hurting.


### Penalty for regression

If any metric **drops below the baseline**, a regression penalty is applied. The penalty is proportional to how far below baseline you fall, multiplied by a penalty strength factor. Adding a rule that causes many false positives (flagging lots of normal traffic as attack) will hurt your precision and trigger a penalty.

### The trade-off

There is a natural tension between precision and recall. Broad rules catch more attacks (higher recall) but also flag more normal traffic (lower precision). Narrow, precise rules do the opposite. Good rules find patterns specific enough to attacks that they do not fire on normal connections. Exploring the training data carefully before writing rules is the most effective strategy.

---

## Submission

Upload **only** `ruleBasedDetection.py` to the Gradescope assignment. Do not upload the dataset, a zip file, or any other files.

Results are returned within seconds of submission. You may resubmit as many times as the assignment allows.
