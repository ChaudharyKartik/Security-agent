# Project Plan

 1. System Goal (Clear Definition) Build a VAPT AI Agent Platform that:

Runs full scans OR specific vulnerability scans

Uses checklist as source of truth

Produces company-standard reports

Learns from analyst feedback

 2. High-Level Architecture (Finalized) Frontend / API ↓ API Gateway (Session + Auth) ↓ Orchestrator Agent ↓ Checklist Agent (brain) ↓ Target Profiling Agent ↓ Specialized Agents:

Web Agent

Network Agent

Cloud Agent ↓ Evidence Agent ↓ CVSS / Risk Agent ↓ Reviewer Agent  Human ↓ Report Agent ↓ Database + Storage ↓ Learning Agent (feedback loop)  3. Core Working Logic Modes: Full Scan

Checklist-Based Scan

Single Vulnerability Scan  (your requirement)

Flow (for single vulnerability): User selects: "SQL Injection" ↓ Checklist Agent validates exact name ↓ Maps → Web Agent ↓ Orchestrator triggers ONLY SQLi test ↓ Evidence → CVSS → Report  4. Business Logic (CRITICAL) Rule 1: Checklist is LAW No free-text vulnerabilities

Only predefined canonical names

Rule 2: Agents are Specialized Web Agent ≠ Network Agent

Each agent only handles its domain

Rule 3: Everything is Structured No raw tool output → everything normalized

Rule 4: Human-in-the-loop High severity MUST be validated

Rule 5: Learning from Feedback Approved → reinforce

Rejected → penalize

 5. Tech Stack (Recommended) Backend FastAPI (you already use it)

Python (agents + tools integration)

Agent Layer LangGraph / custom orchestrator (better: custom for control)

Database PostgreSQL (structured data)

Redis (queue + caching)

Storage S3 / MinIO (screenshots, raw logs)

AI / NLP OpenAI / local LLM (for:

report writing

enrichment

reasoning)

Tools Integration Web: ZAP, Nuclei, SQLMap

Network: Nmap, OpenVAS

Cloud: Prowler

 6. Key Components You Must Define

Checklist Registry All vulnerabilities

Exact names

Agent mapping

Finding Schema Standard structure across system

Agent Contracts Each agent must:

Input: target + checklist item

Output: structured finding

Orchestrator Rules Task routing

Retry logic

Parallel execution

 What NOT to Do  Don’t let tools define output format

 Don’t skip DB (you’ll regret it)

 Don’t mix agents (keep strict boundaries)

 Don’t allow fuzzy checklist names

 What You Should Finalize Next Before coding, define:

 Checklist JSON structure

 Finding JSON schema

 DB schema

 Agent responsibilities (clear boundaries)

 API contract (input/output)

If you want, next step we can do:

 Define exact checklist schema + mapping JSON (this is the foundation of everything)

Today 3:05 PM

some suggestions: sometime there might not be a checklist (example network security testing), refer to OWASP and similar standard sources to define what tests will be covered. so checklist isn't the only source for testing points.

there should be analysis of false positive results and remove if found

there should be a tool based scan too

ChatGPT3:06 PM These are solid additions—they actually fix real gaps in the system. Let’s integrate them properly into the architecture:

 1. “Checklist is not the only source” (VERY IMPORTANT) Fix: Introduce a Test Definition Engine

Sources:

Internal checklist (primary)

OWASP (WSTG, ASVS)

NIST / CIS (for network/cloud)

New Component:  Knowledge Agent

Responsibilities:

If checklist exists → use exact wording

If NOT → fetch from:

OWASP WSTG

Standard vuln taxonomy

Normalize into:

canonical_name source = [internal | OWASP | NIST] test_steps expected_evidence  So system becomes:

Checklist-driven + Standards-driven (fallback)  2. False Positive Analysis (CRITICAL) Add:  False Positive Detection Agent

It should:

Re-run validation with stricter logic

Correlate:

tool output

response behavior

exploit success

Assign:

confidence score (0–1)

Logic: if (exploit fails OR inconsistent evidence): mark = potential_false_positive Then:  Pass to Reviewer Agent / Human

 3. Tool-Based Scanning (YES, but controlled) You don’t want agents replacing tools—you want:

 Agents orchestrating tools

Add:  Tool Integration Layer

Each agent:

Calls tools

Normalizes output

Example:

ZAP → raw alerts  ↓ Web Agent → structured finding  Design Rule: Tool ≠ Source of Truth Agent Output = Source of Truth  Updated Flow (with your suggestions) User Input ↓ Knowledge Agent (Checklist + OWASP fallback) ↓ Orchestrator ↓ Agents (Web / Network / Cloud) ↓ Tool Layer (ZAP, Nmap, etc.) ↓ Evidence Agent ↓ False Positive Agent ↓ CVSS Agent ↓ Reviewer Agent  Human ↓ Report Agent ↓ Database ↓ Learning Agent  Key Design Decisions You Just Introduced

Hybrid Testing Model Checklist (strict)

Standards (flexible fallback)

Trust Pipeline Tool → Agent → FP Detection → Human → Final

Confidence-Based Findings Every finding must have:

confidence_score validation_status  One More Upgrade (Highly Recommended) Add:  Test Strategy Selector

Modes:

Checklist Strict Mode

OWASP Coverage Mode

Full Automated Mode

Specific Vulnerability Mode

You’ve now moved from a scanner → to a real intelligent VAPT platform.

If you want next, we should lock:  final component list + responsibilities (1-page architecture doc)

generate a deeply detailed document containing each and every detail of this project

ChatGPT3:12 PM Alright—here’s a complete, structured, deeply detailed architecture document for your project. This is something you can directly use as a design spec / proposal doc.

 AI-Driven VAPT Platform — System Design Document

 Project Overview Objective Build an AI-powered Vulnerability Assessment & Penetration Testing (VAPT) platform that:

Supports full scans, checklist-based scans, and targeted vulnerability scans

Uses AI agents to orchestrate testing

Integrates industry tools (ZAP, Nmap, etc.)

Produces company-standard reports

Learns from analyst feedback (reinforcement loop)

 Core Principles Agent-Based Architecture

Each function = independent AI agent

No monolithic script execution

Structured Data First

No raw tool outputs in final pipeline

Everything normalized into schemas

Hybrid Intelligence

Internal checklist + OWASP + standards

Human-in-the-loop

Critical findings validated by experts

Learning System

Continuous improvement via feedback

 High-Level Architecture Frontend / API ↓ API Gateway (Session + Auth) ↓ Orchestrator Agent ↓ Knowledge Agent (Checklist + OWASP) ↓ Target Profiling Agent ↓ Specialized Agents:

Web Agent

Network Agent

Cloud Agent ↓ Tool Integration Layer ↓ Evidence Agent ↓ False Positive Detection Agent ↓ Risk Scoring Agent (CVSS) ↓ Reviewer Agent  Human ↓ Report Composer Agent ↓ Database + Storage ↓ Learning Agent

 System Modes 4.1 Full Scan Runs all applicable tests

Uses full recon + all agents

4.2 Checklist-Based Scan Runs only selected checklist items

4.3 Single Vulnerability Scan Runs only ONE test (e.g., SQL Injection)

4.4 Standards Mode (Fallback) Uses OWASP/NIST when checklist not available

 Agent Design 5.1 Orchestrator Agent (Core Brain) Responsibilities:

Task scheduling

Agent routing

Parallel execution

Retry logic

Input:

scan_id

checklist_items

scan_mode

Output:

task execution graph

5.2 Knowledge Agent Purpose: Handles test definitions.

Sources:

Internal checklist

OWASP WSTG

NIST / CIS

Output:

{ canonical_name, source, agent_type, test_steps, expected_evidence } 5.3 Target Profiling Agent Detects:

Web app / API / Network / Cloud

Auth type

Tech stack

5.4 Recon Agent Performs:

Endpoint discovery

Parameter mapping

Headers/cookies collection

5.5 Specialized Agents  Web Agent Handles:

XSS

SQL Injection

CSRF

IDOR

Session issues

Uses:

ZAP

Nuclei

SQLMap

 Network Agent Handles:

Open ports

Weak ciphers

Service exposure

Uses:

Nmap

OpenVAS

 Cloud Agent Handles:

IAM misconfigs

Public exposure

Storage leaks

Uses:

Prowler

 Tool Integration Layer Rule: Tools are execution engines, NOT decision makers

Flow: Tool Output → Agent → Normalized Finding 7.  Evidence Agent Generates:

PoC

Steps to reproduce

Request/response pairs

Screenshots (reference)

 False Positive Detection Agent Logic: Re-validate exploit

Cross-check behavior

Analyze consistency

Output: confidence_score: 0–1 status: valid / false_positive / uncertain 9.  Risk Scoring Agent CVSS v3 calculation

Severity mapping:

Critical

High

Medium

Low

 Reviewer Agent + Human Validation AI Role: Flag high severity

Detect anomalies

Human Role: Approve

Reject

Edit findings

 Report Composer Agent Rules: Title = exact checklist wording

Format = company VAPT template

Sections: Executive Summary

Methodology

Findings:

Description

CVSS

PoC

Impact

Remediation

Conclusion

 Database Design Core Tables: scan_sessions id, target, status, timestamps

scan_jobs job_id, agent, status

checklist_items canonical_name, source, category

scan_job_items scan_id, checklist_item, agent

findings title, severity, cvss, confidence

finding_evidence request, response, payloads

reports report_path, format

analyst_feedback approved/rejected, notes

learning_data signals for RL

 Learning System Inputs: Approved findings

False positives

Severity corrections

Edited remediation

Output: Improved detection

Better scoring

Better report quality

 Finding Schema { finding_id, checklist_item, canonical_title, severity, cvss_score, cvss_vector, category, target, poc, steps_to_reproduce, raw_request, raw_response, impact, remediation, confidence, validation_status }

 Execution Flow (End-to-End) User Input ↓ API Gateway ↓ Orchestrator ↓ Knowledge Agent ↓ Recon Agent ↓ Specialized Agents ↓ Tool Layer ↓ Evidence Agent ↓ False Positive Agent ↓ CVSS Agent ↓ Reviewer + Human ↓ Report Generator ↓ Database Storage ↓ Learning Loop

 Tech Stack Backend FastAPI

Python

Database PostgreSQL

Cache / Queue Redis

Storage S3 / MinIO

AI Layer OpenAI / local LLM

Tools ZAP

Nuclei

SQLMap

Nmap

OpenVAS

Prowler

 Key Constraints Checklist naming must be exact

No raw tool output in reports

All findings must include PoC

High severity must be validated

All results stored for learning

 Future Enhancements Autonomous pentesting agent

Attack chaining (multi-step exploits)

Continuous monitoring mode

Dashboard analytics

Multi-tenant support

 Final Outcome You are building:

A self-improving, agent-based VAPT platform that combines:

Automation

AI reasoning

Industry tools

Human expertise