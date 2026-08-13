//! Prompt templates for the AI layer.

/// The core system prompt describing ANAJAKKH's role.
pub fn system_prompt() -> String {
    concat!(
        "You are ANAJAKKH, an AI-powered Red Team Security Agent operating in a terminal.\n",
        "You are a professional security engineer assisting with authorized security assessments.\n",
        "\n",
        "Guidelines:\n",
        "- Only assess targets that are explicitly authorized and in scope.\n",
        "- Communicate intent, progress, evidence, findings, and next actions clearly.\n",
        "- Never fabricate evidence. Distinguish observed evidence from inference and hypothesis.\n",
        "- Be concise. Use short structured sections.\n",
        "- You never perform destructive or autonomous actions without approval.\n"
    )
    .to_string()
}

/// Prompt asking the planner to break a task into structured steps.
pub fn planner_prompt(task: &str, in_scope_targets: &[String]) -> String {
    let targets = if in_scope_targets.is_empty() {
        "(none detected — ask the user to define scope)".to_string()
    } else {
        in_scope_targets.join(", ")
    };
    format!(
        "Break the following security assessment task into a JSON array of steps.\n\
         Each step: {{\"action\": string, \"description\": string, \"tool\": string|null, \"risk\": \"low|medium|high|critical\"}}\n\
         Use actions from: parse_task, validate_scope, target_discovery, service_enumeration,\n\
         http_inspection, analyze, generate_findings, summarize.\n\n\
         Task: {task}\n\
         Authorized targets: {targets}\n\n\
         Respond with JSON only."
    )
}

/// Prompt asking the provider to propose structured findings from an
/// evidence summary. The response is parsed and validated against the
/// actual evidence records, so the AI can never invent evidence.
pub fn findings_prompt(goal: &str, evidence_summary: &str) -> String {
    format!(
        "You are analyzing evidence from an authorized security assessment.\n\n\
         Goal: {goal}\n\n\
         Evidence records (id | type | target | data):\n{evidence_summary}\n\n\
         Identify security findings grounded in this evidence.\n\
         Respond with ONLY a JSON array. Each element:\n\
         {{\"title\": string, \"severity\": \"critical|high|medium|low|informational\",\n\
           \"confidence\": number 0..1, \"target\": string, \"description\": string,\n\
           \"recommendation\": string, \"evidence_ids\": [ids from the list above],\n\
           \"source\": \"observed|inferred|hypothesis\"}}\n\n\
         Rules:\n\
         - Every evidence_ids entry MUST be an id from the list above. Never invent ids.\n\
         - At least one evidence id per finding.\n\
         - Distinguish observed facts from inference and hypothesis.\n\
         - If the evidence is insufficient, respond with an empty array."
    )
}

/// Prompt used by the executor to analyze plan results.
pub fn analysis_prompt(goal: &str, completed: &str, notes: &str) -> String {
    format!(
        "The agent just completed steps of an assessment. Provide a concise analysis.\n\n\
         Goal: {goal}\n\
         Steps completed: {completed}\n\
         Notes: {notes}\n\n\
         Summarize what was done, what remains, and any immediate next actions."
    )
}
