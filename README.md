# Rule-Based Network Intrusion Detection

**Course Assignment - Gradescope Submission**

---

## Overview

In this assignment you will build a rule-based intrusion detection system using the UNSW-NB15 network traffic dataset. Your goal is to write a set of `if` rules that classify each network connection as either an **attack** or **normal** traffic.

This assignment is intentionally constraint-based. No machine learning, no statistics, no libraries. It is just your understanding of the data and the patterns you find in it.

Two things are being taught here. The first is hands-on: reading a real network security dataset and translating observations into logic. The second is the more important one. **You are going to hit a performance ceiling.** Every rule you add to catch more attacks will start flagging normal traffic, and every rule you tighten to stop flagging normal traffic will start missing attacks. You cannot escape this by being clever. Finding that ceiling, describing where it is, and explaining why it is there is the actual assignment.

**Hitting the ceiling does not mean a low grade.** You are not scored against a perfect detector, and you are not expected to produce one. You are scored on how much you **improve** on the four baseline rules you are given. That is a very achievable target, and strong scores on this assignment are normal. Submit early, look at the per-metric breakdown Gradescope gives you, adjust, and submit again. The ceiling is what you write about in the reflection, not a penalty applied to your score.

---

## Why This Is a Very Real Exercise

What you are writing is a packet filter. A real one. Early internet defense worked exactly this way: an ordered list of static conditions evaluated against each connection, with a default action when nothing matched.

That lineage runs from the first screening routers of the late 1980s, through Bellovin and Cheswick's classification of firewall architectures, to stateful inspection in the mid-1990s, to Linux `ipfwadm`, then `ipchains`, then the netfilter/iptables project that Paul "Rusty" Russell began in 1998 and that shipped in the 2.4 kernel. That model is still the mental furniture behind `nftables`, cloud security groups, and WAF rule sets. Your `detectAttack` function has the same structure as an iptables chain: rules in order, first match wins, default policy at the bottom.

- Bellovin, S. M., & Cheswick, W. R. (1994). Network Firewalls. *IEEE Communications Magazine*, 32(9), 50-57. [DOI](https://doi.org/10.1109/35.312843) | [Free PDF](http://people.scs.carleton.ca/~soma/id/readings/bellovin-firewalls.pdf)
- The netfilter/iptables project: [netfilter.org](https://www.netfilter.org/) | [iptables](https://www.netfilter.org/projects/iptables/index.html)

Signature-based intrusion detection followed the same pattern. Snort, first released in 1998, is a rule language plus a matching engine, and its rule sets are still commercially maintained today. The conceptual frame came earlier, from Dorothy Denning's intrusion detection model, which split the problem into **misuse detection** (match known-bad patterns, which is what you are about to do) and **anomaly detection** (model what normal looks like and flag deviation, which is most of the rest of this course).

- Denning, D. E. (1987). An Intrusion-Detection Model. *IEEE Transactions on Software Engineering*, SE-13(2), 222-232. [DOI](https://doi.org/10.1109/TSE.1987.232894) | [Free PDF](https://www.cs.colostate.edu/~cs656/reading/ieee-se-13-2.pdf)
- Roesch, M. (1999). Snort: Lightweight Intrusion Detection for Networks. *LISA '99*. [Free PDF](https://www.usenix.org/legacy/event/lisa99/full_papers/roesch/roesch.pdf) | [Snort today](https://www.snort.org/)

This is all exceptionally interesting history of internet security, some of you cover this at a high level in Internet Security & Privacy, and Network Security. For those curious, there are more papers that explain the limits you are going to run into. You are not required to read them to complete the assignment, but they will make your reflection much stronger!

- Ptacek, T. H., & Newsham, T. N. (1998). Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection. Secure Networks, Inc. [Full text](https://insecure.org/stf/secnet_ids/secnet_ids.html) | [PDF mirror](https://users.ece.cmu.edu/~adrian/731-sp04/readings/Ptacek-Newsham-ids98.pdf)
  Signature systems can be systematically evaded by an attacker who understands the rules. This is the direct ancestor of the adversarial examples we study later in the semester.
- Axelsson, S. (1999). The Base-Rate Fallacy and its Implications for the Difficulty of Intrusion Detection. *ACM CCS '99*. [DOI](https://doi.org/10.1145/319709.319710). Extended version: *ACM TISSEC* 3(3), 2000. [DOI](https://doi.org/10.1145/357830.357849) | [PDF](https://dl.acm.org/doi/pdf/10.1145/357830.357849)
  Even a highly accurate detector produces mostly false alarms when attacks are rare, because precision depends on how common attacks are and not only on how good your detector is.
- Sommer, R., & Paxson, V. (2010). Outside the Closed World: On Using Machine Learning for Network Intrusion Detection. *IEEE S&P*. [DOI](https://doi.org/10.1109/SP.2010.25) | [Free PDF](https://www.icir.org/robin/papers/oakland10-ml.pdf)
  Swapping rules for machine learning does not automatically fix any of this.

### What "the ceiling" means here

Let us be precise on what 'ceiling' means here, because it is easy to misread as "rule-based systems are bad":

The ceiling is a **performance limit**, not a quality judgement. A rule set can be excellent at what it covers. What it cannot do is cover the space **comprehensively**. Each rule draws a hard boundary along one or two features, and real traffic does not sort itself neatly on either side of those boundaries. Some attacks look, on every feature you can measure, like ordinary traffic. Some ordinary traffic looks, on every feature you can measure, like an attack. The same record can satisfy the conditions of a rule written for one attack category and the conditions of a rule written for another. When a single record legitimately belongs to more than one bucket, no ordering of hard thresholds resolves it correctly for every case.

That is why every gain in one metric starts costing you another once the easy cases are gone. It is a property of drawing hard boundaries through overlapping data, and it is not something you can write your way out of.

None of these systems were retired or supplemented because their authors were careless. They were built by people who understood the problem better than almost anyone. They ran into a limit on how completely a fixed set of thresholds can separate two populations that genuinely overlap, and so will you.

#### A concrete example

Suppose you notice that reconnaissance scans send very few packets and get
nothing back, so you write:

```python
if row['spkts'] <= 2 and row['dpkts'] == 0:
    return True
```

Now look at four connections that all satisfy it:

| Connection | What it actually was | Label |
|---|---|---|
| 2 packets out, 0 back | Port scan probing a closed port | Attack |
| 2 packets out, 0 back | Someone's laptop retrying a DNS server that was down | Normal |
| 1 packet out, 0 back | Shellcode delivery attempt that the host dropped | Attack |
| 1 packet out, 0 back | A monitoring agent health check against an offline service | Normal |

Your rule fires on all four. It is right twice and wrong twice, and nothing
about `spkts` or `dpkts` distinguishes the pairs, because on those two features
the connections are identical.

Try to fix it by tightening the threshold to `spkts <= 1` and you lose the port
scan while keeping one of the false positives. Loosen it to `spkts <= 4` and you
pick up more scans along with more failed lookups. The threshold slides, but the
overlap does not go away, because the boundary is being drawn through a region
where attack and normal traffic genuinely sit on top of each other.

Adding a second condition does not escape this either. It draws a second hard
boundary through the same crowded region and creates a new pair of connections
that are identical on both features and belong to different classes. That is the
ceiling: not a threshold you have not found yet, but the fact that the features
you can see do not always separate the two populations.

---

## The Dataset: UNSW-NB15

The UNSW-NB15 dataset was created by the Australian Centre for Cyber Security at the University of New South Wales. It contains real network packet captures mixed with synthetic attack traffic generated using the IXIA PerfectStorm tool, covering nine attack categories.

**Official dataset page:** https://research.unsw.edu.au/projects/unsw-nb15-dataset

**Citation:**
> Moustafa, N., & Slay, J. (2015). UNSW-NB15: a comprehensive data set for network intrusion detection systems. *2015 Military Communications and Information Systems Conference (MilCIS)*, IEEE.

### Your Training File

You are provided with **`UNSW_NB15_balanced_30k.csv`**, a balanced subset of 30,000 connection records:

| Split | Count |
|-------|-------|
| Normal (`label = 0`) | 15,000 |
| Attack (`label = 1`) | 15,000 |
| **Total** | **30,000** |

The filename matters. The evaluator at the bottom of `ruleBasedDetection.py` looks for `UNSW_NB15_balanced_30k.csv` by exact name and will exit with an error if it cannot find it.

> **Note:** The autograder runs your rules against a separate, unseen dataset drawn from the same source, but may not be balanced. Rules that generalise beyond the training data will score better than rules tuned to specific rows.

### Attack Categories in the Dataset

| Category | Description |
|---|---|
| Fuzzers | Sending random or semi-random data to find crashes or unexpected behaviour |
| Analysis | Port scans, spam, and HTML file infiltration |
| Backdoors | Secret bypass of normal authentication |
| DoS | Denial-of-service attacks aimed at exhausting target resources |
| Exploits | Attacks leveraging known software vulnerabilities |
| Generic | Attacks targeting block-cipher-based encryption |
| Reconnaissance | Information gathering, probing and scanning |
| Shellcode | Injecting and executing arbitrary shellcode |
| Worms | Self-replicating malware spreading across networks |

These categories do not behave alike. A Generic attack and a Reconnaissance scan can look quite different, and a rule tuned for one will typically be blind to the other. This is one of the reasons a single rule set struggles to cover the whole label!

### Feature Reference

All features used in your rules are numeric. The `label` column is the ground truth.

**You may not reference `label` or `attack_cat` in your rules.** Both are ground truth and using either is leakage. The autograder checks for this and will award a score of 0. **Do not use either in your rules**.

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
| `label` | Ground truth: 0 = Normal, 1 = Attack. **Banned in rules** |

---

## Your Task

Open `ruleBasedDetection.py`. You will find a function called `detectAttack(row)` with four pre-populated baseline rules. Add more rules **below** the marked line to improve classification performance.

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

**Do not modify, reorder, or delete the four baseline rules.** Your score is measured relative to them, so the autograder verifies they are intact. Add your own rules only in the marked section below them.

### Writing Your Own Rules

Each rule is a single `if` statement that returns `True` for a predicted attack:

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

There is no limit on how many rules you add. However, you'll notice the ceiling limit fast approaching. The baseline rules are partially to blame here too, this is on purpose!

### Watch Out for Division by Zero

Ratios are useful, but many rows contain zeros and you are not allowed to call helper functions to guard against that. Use Python's short-circuit evaluation instead. Put the guard first, joined by `and`:

```python
# WRONG: crashes on any row where dbytes == 0
if row['sbytes'] / row['dbytes'] > 50:
    return True

# RIGHT: the second condition is never evaluated when the first is False
if row['dbytes'] > 0 and row['sbytes'] / row['dbytes'] > 50:
    return True
```

An uncaught exception during grading scores 0 for that submission, so test locally before you submit!

### A Note on "Balanced"

Your dataset is balanced: exactly half the records are attacks. Real networks are not. On a production link, attacks are typically a fraction of a percent of connections, sometimes far less. That gap is called the **base rate**, and it matters more than people expect.

Nothing about a rule set changes when the base rate changes, but its metrics do. Suppose your rules fire on 5% of normal traffic and catch 80% of attacks. On this balanced file, that is roughly 12,000 true positives against 750 false positives, so precision looks strong. Put the identical rules on a link carrying 1% attacks and you get roughly 240 true positives against 1,485 false positives. Precision collapses below 15%. Accuracy actually goes up, because almost everything is normal and you are correctly ignoring most of it.

You are not being asked to do anything about this, and it does not affect your grade. It is worth knowing because it explains two things you will run into for the rest of your career: why security operations teams talk about alert fatigue, and why "our model achieved 99% accuracy" is a claim to be suspicious of until you know what fraction of the data was actually the thing being detected. Axelsson's paper, linked above, is the formal version of this argument.

---

## Rules and Constraints

These apply to **the body of the `detectAttack` function only** and are enforced automatically. Violations result in a score of **0**.

| Allowed inside `detectAttack` | Not allowed inside `detectAttack` |
|---|---|
| `if / elif / else` | `import` statements of any kind |
| `==  !=  >  <  >=  <=` | Function calls (`abs()`, `len()`, `max()`, etc.) |
| `and  or  not` | List, set, or dictionary comprehensions |
| `+  -  *  /` inside conditions | Loops (`for`, `while`) |
| `return True` / `return False` | Machine learning or statistics libraries |
| Dictionary lookups like `row['dur']` | Defining new functions or classes |
| | Referencing `label` or `attack_cat` |

The rest of the file, including the `evaluateDetector` function and the `__main__` block, is not checked and does not need to be removed. You may edit it locally for your own testing, since only `detectAttack` is graded. Submit the whole file regardless.

---

## Testing Locally

```bash
python ruleBasedDetection.py
```

Make sure `UNSW_NB15_balanced_30k.csv` is in the same folder. Test as often as you like. Only your Gradescope submission counts for marks.

Keep the file named `ruleBasedDetection.py` while you work, since the evaluator block at the bottom expects to be run that way. Rename it to `<netid>_ite.py` only when you are ready to submit. See [Submission](#submission) for the exact naming rules.

**Explore before you write.** You are allowed to analyse the training CSV however you want, including with pandas, a notebook, Excel, `awk`, superstitious rituals, whatever helps you in your process. The constraints apply only to the rules you submit, not to how you discover them. Students who plot a few feature distributions by label before writing anything consistently outperform students who guess and resubmit. We recommend using your brain on this, so you learn how to look at data and their shape.

---

## Grading

Your submission is graded against a separate, unseen dataset! Your score is based on how much you improve each metric **relative to the four baseline rules**. Metrics that improve are rewarded; metrics that drop below the baseline are penalised.

You are not graded against 100% on anything. Nobody reaches that here, and the assignment is not designed for it. The bar is improvement over the baseline, which is very reachable. **Submit to Gradescope early and often.** You get a per-metric breakdown within seconds, so treat it as your feedback loop rather than saving one submission for the deadline.

For reference, here is how the four baseline rules alone perform on the hidden dataset:

| Metric | Baseline |
|---|---|
| Accuracy | XX.X% |
| Precision | XX.X% |
| Recall | XX.X% |
| F1 | XX.X% |

You will see a per-metric breakdown on Gradescope after each submission so you can see exactly which metrics your rules are helping or hurting.

### Penalty for regression

If any metric drops below the baseline, a regression penalty is applied, proportional to how far below baseline you fall. Adding a rule that causes many false positives, meaning it flags lots of normal traffic as attack, will hurt your precision and trigger a penalty (score decrease).

### The strategies that do not work

Two ideas will occur to almost everyone. Both fail, and it is worth understanding why before you spend a submission on them:

- **Flag everything as an attack.** Recall goes to 100%, which looks great. Precision falls to roughly the attack rate of the dataset and accuracy falls with it. On the hidden set this lands well below baseline on two metrics and the regression penalty eats the gains.
- **Flag almost nothing, using one extremely narrow rule.** Precision can approach 100%. Recall collapses, F1 collapses with it, and you are penalised again.

The scoring is deliberately built so that neither corner of the trade-off is a winning move. You are being pushed toward the middle, where the real difficulty lives.
In Computer Science and Game Theory we call this, 'degenerate strategies'. Which are tactics that exploits a game design flaw to guarantee success or maximize efficiency with minimal thought.

### The trade-off

Broad rules catch more attacks (higher recall) but also flag more normal traffic (lower precision). Narrow rules do the opposite. Good rules find patterns specific enough to attacks that they do not fire on normal connections.

You will find that this gets harder, not easier, as you add rules. Your first two or three additions will probably help, and that is where most of your score comes from. Somewhere after that, each new rule will start taking back as much as it gives, because the connections you have not caught yet are the ones that genuinely resemble normal traffic on every feature you have available. That is not a failure of imagination. It is the shape of the problem, and noticing exactly where it happened to you is worth more than another point of F1.

---

## Where This Goes Next

Keep your final metrics in mind. In the next assignment you will run a learned model on this same data and compare.

The comparison is more interesting than it first appears. A decision tree is also a rule-based system: it is a nested chain of threshold comparisons on individual features, structurally identical to what you are writing here. The difference is that its thresholds are fit from data rather than chosen by you, and there are far more of them. Some of the ceiling you hit this week will lift. Some of it will not, and the part that does not lift is the part worth understanding.

---

## Submission

### Naming your file

Rename your file before you submit. Gradescope expects exactly:

`<netid>_ite.py`

`<netid>` is your NYU netid, the part of your NYU email address before the `@`. The `ite` stands for *if-then-else*.

| Your NYU email | Your netid | Your filename |
|---|---|---|
| `abc1234@nyu.edu` | `abc1234` | `abc1234_ite.py` |
| `jd987@nyu.edu` | `jd987` | `jd987_ite.py` |

**The filename is checked before anything is graded. If it does not match this pattern, the submission is rejected and no score is recorded.** This is not a style preference. It is how your submission gets attached to you.

Get these right:

- Write your netid in **lowercase**. (The check itself is case-insensitive, so `ABC1234_ITE.py` will not be rejected, but lowercase is the expected form.)
- Put an **underscore** between your netid and `ite`, not a hyphen, a dot, or a space.
- The name ends at `.py`. Nothing comes after it.
- The file must not be empty.
- Use **your own** netid. Submitting under another student's netid is academic misconduct, and it is checked for.

Names that get rejected:

| Rejected filename | Why it fails |
|---|---|
| `ruleBasedDetection.py` | you forgot to rename it |
| `abc1234-ite.py` | hyphen instead of an underscore |
| `abc1234ite.py` | missing underscore |
| `abc1234_ite.txt` | wrong extension |
| `abc1234_ite.py.txt` | hidden second extension |
| `abc1234 ite.py` | space instead of an underscore |
| `assignment1.py` | does not follow the pattern |

> **On Windows**, turn on File Explorer -> View -> File name extensions before renaming. With extensions hidden, a file that displays as `abc1234_ite.py` can actually be `abc1234_ite.py.txt`, and renaming it will not do what you expect.

### What to upload

Upload to the Gradescope assignment:

1. **`<netid>_ite.py`**, which is your `ruleBasedDetection.py` with your rules added and renamed as above. Upload the file itself, not a zip and not the dataset.

Autograder results are returned within gradescope. You may resubmit as many times as the assignment allows (read output carefully to find this).
