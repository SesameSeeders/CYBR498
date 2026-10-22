# CYBR498

This is my Senior capstone research repo, which support my research paper Comparing Static and Dynamic Techniques Against Malware using Python.

## The Observations

As stated in my thesis, static analysis is usually the first step in malware triage because it is fast, safe, and cheap. Malware authors know that, so a lot of modern malware is packed, obfuscated, or encrypted to trick the analyst into thinking is it safe to run. This project compares what static analysis can find against what a sandbox
run finds, using two samples with different levels of obfuscation:

- WannaCry ransomware (less obfuscated)
- Agent Tesla info-stealer (more obfuscated, .NET)

The goal is to find the point where static analysis stops being useful on its own and dynamic
analysis becomes necessary.

## Included in the Repo

The Python tooling for the static side of the comparison. The dynamic side comes from public
sandbox reports and is not in this repo.

To keep things safe, live malware samples aren't committed. See `.gitignore` to verify.