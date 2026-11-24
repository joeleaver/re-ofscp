//! The console's own CSS: layout, tables and the one-time secret panels.
//! Components bring their own styles; colours come from the rinch theme.

/// Global styles.
pub const CSS: &str = r#"
* { box-sizing: border-box; }

html, body {
    margin: 0;
    min-height: 100vh;
    font-family: var(--rinch-font-family);
    background: var(--rinch-color-body);
    color: var(--rinch-color-text);
}

.centered {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--rinch-spacing-md);
}

.card {
    width: 100%;
    max-width: 440px;
    padding: var(--rinch-spacing-xl);
    border: 1px solid var(--rinch-color-gray-3);
    border-radius: var(--rinch-radius-md);
    background: var(--rinch-color-body);
}

.card.wide { max-width: 560px; }

.shell {
    display: flex;
    min-height: 100vh;
}

.sidebar {
    width: 220px;
    min-width: 220px;
    padding: var(--rinch-spacing-md);
    border-right: 1px solid var(--rinch-color-gray-3);
    display: flex;
    flex-direction: column;
    gap: var(--rinch-spacing-xs);
}

.sidebar .brand {
    font-weight: 700;
    font-size: 1.1rem;
    padding: var(--rinch-spacing-xs) var(--rinch-spacing-sm) var(--rinch-spacing-md);
}

.nav-item {
    display: block;
    width: 100%;
    text-align: left;
    padding: 8px 12px;
    border: none;
    border-radius: var(--rinch-radius-sm);
    background: transparent;
    color: inherit;
    font: inherit;
    cursor: pointer;
}

.nav-item:hover:not(.unavailable) { background: var(--rinch-color-gray-1); }
.nav-item.active { background: var(--rinch-color-blue-1); color: var(--rinch-color-blue-8); font-weight: 600; }
.nav-item.unavailable { color: var(--rinch-color-dimmed); cursor: not-allowed; }
.nav-item .hint { display: block; font-size: 0.75rem; font-weight: 400; }

.main {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
}

.topbar {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: var(--rinch-spacing-md);
    padding: var(--rinch-spacing-sm) var(--rinch-spacing-xl);
    border-bottom: 1px solid var(--rinch-color-gray-3);
}

.content {
    padding: var(--rinch-spacing-xl);
    display: flex;
    flex-direction: column;
    gap: var(--rinch-spacing-lg);
    max-width: 1200px;
}

.panel {
    padding: var(--rinch-spacing-lg);
    border: 1px solid var(--rinch-color-gray-3);
    border-radius: var(--rinch-radius-md);
    display: flex;
    flex-direction: column;
    gap: var(--rinch-spacing-sm);
}

.row {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-end;
    gap: var(--rinch-spacing-sm);
}

.row > .grow { flex: 1; min-width: 180px; }

.table-wrap { overflow-x: auto; }

table.data {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
}

table.data th, table.data td {
    text-align: left;
    padding: 8px 10px;
    border-bottom: 1px solid var(--rinch-color-gray-3);
    vertical-align: middle;
}

table.data th { font-weight: 600; color: var(--rinch-color-dimmed); white-space: nowrap; }
table.data td.mono, .mono { font-family: var(--rinch-font-family-monospace, monospace); overflow-wrap: anywhere; }
table.data td.nowrap { white-space: nowrap; overflow-wrap: normal; }
table.data td.actions { white-space: nowrap; text-align: right; }

.link-button {
    border: none;
    background: none;
    padding: 0;
    color: var(--rinch-color-blue-7);
    font: inherit;
    cursor: pointer;
    text-decoration: underline;
}

.secret {
    padding: var(--rinch-spacing-md);
    border: 2px solid var(--rinch-color-yellow-6);
    border-radius: var(--rinch-radius-md);
    background: var(--rinch-color-yellow-0);
    color: var(--rinch-color-dark-9, #1a1b1e);
    display: flex;
    flex-direction: column;
    gap: var(--rinch-spacing-sm);
}

.secret-value {
    display: flex;
    align-items: center;
    gap: var(--rinch-spacing-sm);
}

.secret-value code {
    flex: 1;
    padding: 6px 8px;
    border-radius: var(--rinch-radius-sm);
    background: #ffffff;
    word-break: break-all;
}

.qr { display: block; width: 220px; height: 220px; image-rendering: pixelated; }

.field-label { font-size: 0.875rem; font-weight: 500; margin-bottom: 4px; display: block; }

.native-input {
    width: 100%;
    height: 36px;
    padding: 0 10px;
    border: 1px solid var(--rinch-color-gray-4);
    border-radius: var(--rinch-radius-sm);
    background: var(--rinch-color-body);
    color: inherit;
    font: inherit;
}

.muted { color: var(--rinch-color-dimmed); font-size: 0.875rem; }
"#;
