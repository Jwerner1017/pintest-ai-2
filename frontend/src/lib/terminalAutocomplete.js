export const COMMAND_VERBS = [
    'help', 'clear', 'whoami', 'scans', 'scan', 'vuln', 'netscan',
    'cancel', 'summary', 'xml', 'ai',
];

export const PRESET_NAMES = ['fast', 'thorough', 'stealth'];
const SCAN_ID_VERBS = new Set(['cancel', 'summary', 'xml']);
const SCAN_VERBS = new Set(['scan', 'vuln', 'netscan']);

export function completionNeedsScanIds(value) {
    const tokens = value.trimStart().split(/\s+/);
    return tokens.length === 2 && SCAN_ID_VERBS.has(tokens[0]?.toLowerCase());
}

export function getTerminalCompletions(value, scanIds = []) {
    const normalized = value.trimStart();
    const tokens = normalized.split(/\s+/);
    const query = tokens[tokens.length - 1]?.toLowerCase() || '';
    const replaceStart = value.lastIndexOf(' ') + 1;
    let options = [];
    let kind = 'command';

    if (tokens.length === 1) {
        options = COMMAND_VERBS;
    } else if (tokens.length === 2 && SCAN_ID_VERBS.has(tokens[0].toLowerCase())) {
        options = scanIds.map((id) => query.length > 8 ? id : id.slice(0, 8));
        kind = 'scan';
    } else if (tokens.length === 3 && SCAN_VERBS.has(tokens[0].toLowerCase())) {
        options = PRESET_NAMES;
        kind = 'preset';
    }

    const matches = [...new Set(options.filter((option) => option.toLowerCase().startsWith(query)))];
    return { kind, matches, replaceStart };
}