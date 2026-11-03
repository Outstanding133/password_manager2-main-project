/**
 * CIPHER - Password Vault Frontend Controller
 * Premium Neo-Brutalist SPA, PBKDF2 cryptography client, & visual state manager.
 */

// ==========================================================================
// Application State
// ==========================================================================
const state = {
    csrfToken: null,
    passwords: [],
    activeTab: 'dashboard',
    activeFilter: 'all',
    searchQuery: '',
    editingId: null,
    deleteId: null,
    selectedId: null,
    autoLockTimer: null,
    AUTO_LOCK_MS: 5 * 60 * 1000, // 5 minutes inactivity
    newRotatedPassword: null,
};

// ==========================================================================
// REST API Cryptography Client
// ==========================================================================
const api = {
    async request(url, options = {}) {
        const method = (options.method || 'GET').toUpperCase();
        const headers = {
            'Content-Type': 'application/json',
            ...(options.headers || {}),
        };

        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
            if (!state.csrfToken) {
                throw new Error('Security token is missing. Please reload the page.');
            }
            headers['X-CSRF-Token'] = state.csrfToken;
        }

        const res = await fetch(url, {
            ...options,
            method,
            headers,
            credentials: 'same-origin',
        });
        const contentType = res.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Request failed');
            return data;
        } else {
            const text = await res.text();
            throw new Error(`Server returned non-JSON response. Please reload.`);
        }
    },

    csrf()                                       { return this.request('/api/csrf'); },
    status()                                     { return this.request('/api/status'); },
    setup(master_password)                       { return this.request('/api/setup', { method: 'POST', body: JSON.stringify({ master_password }) }); },
    unlock(master_password)                      { return this.request('/api/unlock', { method: 'POST', body: JSON.stringify({ master_password }) }); },
    lock()                                       { return this.request('/api/lock', { method: 'POST' }); },
    getPasswords()                               { return this.request('/api/passwords'); },
    addPassword(data)                            { return this.request('/api/passwords', { method: 'POST', body: JSON.stringify(data) }); },
    updatePassword(id, data)                     { return this.request(`/api/passwords/${id}`, { method: 'PUT', body: JSON.stringify(data) }); },
    deletePassword(id)                           { return this.request(`/api/passwords/${id}`, { method: 'DELETE' }); },
    generate(opts)                               { return this.request('/api/generate', { method: 'POST', body: JSON.stringify(opts) }); },
    analyze(password)                            { return this.request('/api/analyze', { method: 'POST', body: JSON.stringify({ password }) }); },
    stats()                                      { return this.request('/api/stats'); },
    changeMaster(current_password, new_password) { return this.request('/api/change-master', { method: 'POST', body: JSON.stringify({ current_password, new_password }) }); },
};

// ==========================================================================
// Core UI Utilities & Helpers
// ==========================================================================
function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

function showView(viewId) {
    $$('.view').forEach(v => v.classList.remove('active'));
    const el = $(`#view-${viewId}`);
    if (el) el.classList.add('active');
}

function showTab(tabName) {
    state.activeTab = tabName;
    
    // Dynamically adjust Neo-Brutalist styling classes for tabs
    $$('.nav-tab').forEach(btn => {
        if (btn.dataset.tab === tabName) {
            btn.classList.add('bg-primary-container', 'text-on-primary-container', 'border-primary', 'shadow-[4px_4px_0px_0px_rgba(26,26,26,1)]', 'font-bold');
            btn.classList.remove('border-transparent', 'hover:bg-primary', 'hover:text-white');
        } else {
            btn.classList.remove('bg-primary-container', 'text-on-primary-container', 'border-primary', 'shadow-[4px_4px_0px_0px_rgba(26,26,26,1)]', 'font-bold');
            btn.classList.add('border-transparent', 'hover:bg-primary', 'hover:text-white');
        }
    });

    $$('.tab-content').forEach(c => c.classList.add('hidden'));
    const contentTab = $(`#tab-content-${tabName}`);
    if (contentTab) contentTab.classList.remove('hidden');

    if (tabName === 'dashboard') loadDashboard();
    if (tabName === 'vault') loadVault();
    if (tabName === 'generator') handleGenerateView();
    if (tabName === 'security') resetSecurityForm();
}

function toast(message, type = 'info') {
    const container = $('#toast-container');
    if (!container) return;
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    const icons = { success: '⚡ SUCCESS:', error: '🚨 ERROR:', info: 'ℹ️ INFO:' };
    el.innerHTML = `<span>${icons[type] || ''}</span> <span>${message}</span>`;
    container.appendChild(el);
    setTimeout(() => {
        el.classList.add('removing');
        el.addEventListener('animationend', () => el.remove());
    }, 3000);
}

function getStrengthAttr(score) {
    if (score >= 80) return 'vstrong';
    if (score >= 60) return 'strong';
    if (score >= 40) return 'fair';
    if (score >= 20) return 'weak';
    return 'vweak';
}

function updateStrengthUI(prefix, analysis) {
    const bar = $(`#${prefix}-strength-bar`);
    const rating = $(`#${prefix}-strength-rating`);
    const entropy = $(`#${prefix}-strength-entropy`);
    const attr = getStrengthAttr(analysis.score);
    
    if (bar) {
        bar.setAttribute('data-score', attr);
        bar.style.width = `${analysis.score}%`;
    }
    if (rating) {
        rating.textContent = analysis.rating;
        rating.setAttribute('data-score', attr);
    }
    if (entropy) {
        entropy.textContent = `${analysis.entropy} bits / Score: ${analysis.score}`;
    }

    const fbList = $(`#${prefix}-strength-feedback`);
    if (fbList && analysis.feedback) {
        fbList.innerHTML = analysis.feedback.map(f => {
            const passed = f.includes('!') || f.includes('password') || f.includes('strong');
            return `<li class="flex items-center gap-1.5 ${passed ? 'text-primary' : 'text-secondary'}">
                <span class="material-symbols-outlined text-[12px] font-bold">${passed ? 'check_circle' : 'cancel'}</span>
                <span>${f}</span>
            </li>`;
        }).join('');
    }
}

function resetAutoLock() {
    clearTimeout(state.autoLockTimer);
    state.autoLockTimer = setTimeout(async () => {
        try { await api.lock(); } catch {}
        showView('unlock');
        toast('Vault locked due to inactivity', 'info');
    }, state.AUTO_LOCK_MS);
}

// ==========================================================================
// Initialization & Entry Points
// ==========================================================================
document.addEventListener('DOMContentLoaded', async () => {
    try {
        const csrfData = await api.csrf();
        state.csrfToken = csrfData.csrf_token;

        const status = await api.status();
        if (!status.master_set) {
            showView('setup');
        } else if (status.unlocked) {
            showView('main');
            showTab('dashboard');
            resetAutoLock();
        } else {
            showView('unlock');
        }
    } catch {
        showView('setup');
    }

    bindEvents();
});

// ==========================================================================
// Event Listeners & Bindings
// ==========================================================================
function bindEvents() {
    // --- Authentication ---
    $('#setup-form').addEventListener('submit', handleSetup);
    $('#unlock-form').addEventListener('submit', handleUnlock);

    // --- SideNavBar Navigation Links ---
    $$('.nav-tab').forEach(tab => {
        tab.addEventListener('click', () => showTab(tab.dataset.tab));
    });

    // --- Inactivity & Logout Lock ---
    $('#btn-lock').addEventListener('click', async () => {
        await api.lock();
        clearTimeout(state.autoLockTimer);
        showView('unlock');
        toast('Vault locked', 'info');
    });

    // --- Sidebar Unified Credential Modal Trigger ---
    $('#btn-sidebar-add').addEventListener('click', () => openPasswordModal(null));

    // --- Unified Modal Close / Cancel ---
    $('#modal-close-btn').addEventListener('click', closePasswordModal);
    $('#modal-cancel-btn').addEventListener('click', closePasswordModal);
    $('#modal-save-btn').addEventListener('click', handleSaveEditPassword);
    $('#modal-password').addEventListener('click', e => { if (e.target.id === 'modal-password') closePasswordModal(); });

    // --- Delete Confirmation Overlay ---
    $('#confirm-cancel').addEventListener('click', () => { $('#modal-confirm').classList.remove('active'); state.deleteId = null; });
    $('#confirm-delete').addEventListener('click', handleConfirmDelete);
    $('#modal-confirm').addEventListener('click', e => { if (e.target.id === 'modal-confirm') { $('#modal-confirm').classList.remove('active'); state.deleteId = null; } });

    // --- Live Filtering Search ---
    $('#search-input').addEventListener('input', e => {
        state.searchQuery = e.target.value.toLowerCase();
        renderVaultList();
    });

    // --- Category Filters Chips ---
    $$('.filter-chip').forEach(chip => {
        chip.addEventListener('click', () => {
            $$('.filter-chip').forEach(c => {
                c.classList.remove('border-primary', 'bg-white');
                c.classList.add('border-transparent');
            });
            chip.classList.remove('border-transparent');
            chip.classList.add('border-primary', 'bg-white');
            state.activeFilter = chip.dataset.category;
            renderVaultList();
        });
    });

    // --- Universal View/Hide Password Toggles ---
    $$('.password-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = $(`#${btn.dataset.target}`);
            if (target) {
                target.type = target.type === 'password' ? 'text' : 'password';
                const icon = btn.querySelector('.material-symbols-outlined');
                if (icon) {
                    icon.textContent = target.type === 'password' ? 'visibility' : 'visibility_off';
                }
            }
        });
    });

    // --- Live Strength Auditing on Setup ---
    $('#setup-password').addEventListener('input', async e => {
        const pw = e.target.value;
        if (pw.length === 0) { updateStrengthUI('setup', { score: 0, rating: 'EMPTY', entropy: 0, feedback: [] }); return; }
        try {
            const analysis = await api.analyze(pw);
            updateStrengthUI('setup', analysis);
        } catch {}
    });

    // --- Live Strength Auditing inside Modal ---
    $('#pw-password').addEventListener('input', async e => {
        const pw = e.target.value;
        if (pw.length === 0) { updateStrengthUI('pw', { score: 0, rating: 'EMPTY', entropy: 0 }); return; }
        try {
            const analysis = await api.analyze(pw);
            updateStrengthUI('pw', analysis);
        } catch {}
    });

    // --- Unified Modal Inline Quick Generator ---
    $('#gen-modal-generate').addEventListener('click', async () => {
        const length = parseInt($('#gen-modal-length').value);
        try {
            const data = await api.generate({ length });
            $('#gen-modal-output').value = data.password;
        } catch {}
    });
    $('#gen-modal-length').addEventListener('input', e => { $('#gen-modal-length-val').textContent = e.target.value; });
    $('#gen-modal-use').addEventListener('click', () => {
        const gen = $('#gen-modal-output').value;
        if (gen) {
            $('#pw-password').value = gen;
            $('#pw-password').type = 'text';
            const toggleIcon = document.querySelector('.password-toggle[data-target="pw-password"] .material-symbols-outlined');
            if (toggleIcon) toggleIcon.textContent = 'visibility_off';
            $('#pw-password').dispatchEvent(new Event('input'));
            toast('Password applied!', 'success');
        }
    });

    // --- Standalone Generator Slider & Config Toggles ---
    $('#gen-view-length').addEventListener('input', e => {
        $('#gen-view-length-val').textContent = e.target.value;
        handleGenerateView();
    });
    $('#gen-view-copy').addEventListener('click', () => {
        const pw = $('#gen-view-output').textContent;
        if (pw && pw !== 'CLICK_GENERATE...') {
            navigator.clipboard.writeText(pw);
            toast('Copied standalone output!', 'success');
        }
    });
    $$('.gen-toggle').forEach(btn => {
        btn.classList.add('active'); // Default active
        btn.addEventListener('click', () => {
            btn.classList.toggle('active');
            if (btn.classList.contains('active')) {
                btn.classList.remove('grayscale', 'opacity-50', 'bg-surface-variant');
                btn.classList.add('bg-primary-container');
            } else {
                btn.classList.add('grayscale', 'opacity-50', 'bg-surface-variant');
                btn.classList.remove('bg-primary-container');
            }
            handleGenerateView();
        });
    });

    // --- Live Strength Auditing inside Standalone Analyzer ---
    let analyzerDebounce = null;
    $('#analyzer-input').addEventListener('input', e => {
        clearTimeout(analyzerDebounce);
        analyzerDebounce = setTimeout(() => handleAnalyze(e.target.value), 300);
    });

    // --- Security Rotate Form Submissions ---
    $('#security-form').addEventListener('submit', handleSecurityChange);

    // --- Live Strength Auditing inside Security Rotation Form ---
    $('#security-new-password').addEventListener('input', async e => {
        const pw = e.target.value;
        if (pw.length === 0) { updateStrengthUI('security', { score: 0, rating: 'EMPTY', entropy: 0, feedback: [] }); return; }
        try {
            const analysis = await api.analyze(pw);
            updateStrengthUI('security', analysis);
        } catch {}
    });

    // --- OTMP Master Password Rotation Modal Trackers & Checklist ---
    const chkCopy = $('#rotation-chk-copy');
    const chkUseless = $('#rotation-chk-useless');
    const btnConfirm = $('#btn-rotation-confirm');

    function updateConfirmButtonState() {
        btnConfirm.disabled = !(chkCopy.checked && chkUseless.checked);
    }

    chkCopy.addEventListener('change', updateConfirmButtonState);
    chkUseless.addEventListener('change', updateConfirmButtonState);

    $('#btn-rotation-copy').addEventListener('click', () => {
        const pw = state.newRotatedPassword || $('#rotation-password-val').textContent;
        navigator.clipboard.writeText(pw);
        toast('Copied rotated master key!', 'success');
        
        // Track the click to enable the lockout prevention list item (user must check manually)
        chkCopy.disabled = false;
        const lblCopy = $('#rotation-label-copy');
        if (lblCopy) {
            lblCopy.classList.remove('text-primary/40', 'cursor-not-allowed', 'pointer-events-none');
            lblCopy.classList.add('cursor-pointer');
        }
        updateConfirmButtonState();
    });

    $('#btn-rotation-download').addEventListener('click', () => {
        const pw = state.newRotatedPassword || $('#rotation-password-val').textContent;
        const blob = new Blob([
            "============================================================\n",
            "CIPHER VAULT - ROTATED SINGLE-USE MASTER PASSWORD\n",
            "============================================================\n",
            `Generated: ${new Date().toLocaleString()}\n`,
            "Save this password. It is mandatory for your very next unlock.\n",
            "Once you access the vault again, it will rotate dynamically\n",
            "and this one will be permanently worthless.\n\n",
            `ROTATED MASTER PASSWORD: ${pw}\n`,
            "============================================================\n"
        ], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cipher_rotated_master_key_${new Date().toISOString().slice(0, 10)}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast('Backup file downloaded!', 'success');
        
        // Track the click to enable the lockout prevention list item (user must check manually)
        chkCopy.disabled = false;
        const lblCopy = $('#rotation-label-copy');
        if (lblCopy) {
            lblCopy.classList.remove('text-primary/40', 'cursor-not-allowed', 'pointer-events-none');
            lblCopy.classList.add('cursor-pointer');
        }
        updateConfirmButtonState();
    });

    btnConfirm.addEventListener('click', () => {
        $('#modal-rotation').style.display = 'none';
        showView('main');
        showTab('dashboard');
        resetAutoLock();
    });

    // --- Action bindings for inactivity locks ---
    ['click', 'keydown', 'mousemove', 'scroll'].forEach(evt => {
        document.addEventListener(evt, () => {
            if ($('#view-main').classList.contains('active')) resetAutoLock();
        }, { passive: true });
    });
}

// ==========================================================================
// Authentication Event Handlers
// ==========================================================================
async function handleSetup(e) {
    e.preventDefault();
    const pw = $('#setup-password').value;
    const confirm = $('#setup-confirm').value;
    const errEl = $('#setup-error');
    const btn = $('#setup-btn');

    errEl.classList.add('hidden');

    if (pw !== confirm) {
        errEl.textContent = 'Setup failure: Passwords do not match';
        errEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;

    try {
        await api.setup(pw);
        toast('Setup complete! Vault derived successfully', 'success');
        showView('main');
        showTab('dashboard');
        resetAutoLock();
    } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
    }
}

async function handleUnlock(e) {
    e.preventDefault();
    const pw = $('#unlock-password').value;
    const errEl = $('#unlock-error');
    const btn = $('#unlock-btn');

    errEl.classList.add('hidden');
    btn.disabled = true;

    try {
        const res = await api.unlock(pw);
        toast('Access granted! Unlocking cipher container', 'success');
        
        if (res.rotated_password) {
            // Display OTMP rotation modal alert
            $('#rotation-password-val').textContent = res.rotated_password;
            $('#modal-rotation').style.display = 'flex';
            
            state.newRotatedPassword = res.rotated_password;
            $('#unlock-password').value = '';
            
            // Lockout checkers reset
            $('#rotation-chk-copy').checked = false;
            $('#rotation-chk-copy').disabled = true;
            const lblCopy = $('#rotation-label-copy');
            if (lblCopy) {
                lblCopy.classList.add('text-primary/40', 'cursor-not-allowed', 'pointer-events-none');
                lblCopy.classList.remove('cursor-pointer');
            }
            $('#rotation-chk-useless').checked = false;
            $('#btn-rotation-confirm').disabled = true;
        } else {
            $('#unlock-password').value = '';
            showView('main');
            showTab('dashboard');
            resetAutoLock();
        }
    } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
    }
}

// ==========================================================================
// Dashboard View Flow
// ==========================================================================
async function loadDashboard() {
    try {
        const [statsData, passwords] = await Promise.all([api.stats(), api.getPasswords()]);
        state.passwords = passwords;

        $('#stat-total').textContent = statsData.total;
        $('#stat-weak').textContent = statsData.weak;
        $('#stat-categories').textContent = statsData.categories.length;
        $('#stat-strong').textContent = Math.max(0, statsData.total - statsData.weak);

        const recentList = $('#recent-list');
        const recent = passwords.slice(0, 6);

        if (recent.length === 0) {
            recentList.innerHTML = `
                <div class="col-span-full border-4 border-dashed border-primary p-12 text-center bg-white neo-shadow">
                    <span class="material-symbols-outlined text-5xl text-on-surface-variant">lock</span>
                    <h4 class="font-headline font-black text-xl uppercase mt-4">Database Empty</h4>
                    <p class="text-xs text-on-surface-variant font-medium mt-1">Start by clicking 'New Entry' to save credentials.</p>
                </div>
            `;
        } else {
            recentList.innerHTML = recent.map(pw => renderRecentPasswordItem(pw)).join('');
            
            // Wire click to jump to vault tab & select the row
            recentList.querySelectorAll('.recent-item').forEach(card => {
                card.onclick = () => {
                    const id = parseInt(card.dataset.id);
                    showTab('vault');
                    setTimeout(() => selectCredential(id), 50);
                };
            });
        }
    } catch (err) {
        if (err.message === 'Vault is locked') { showView('unlock'); return; }
        toast('Failed to load dashboard statistics', 'error');
    }
}

function renderRecentPasswordItem(pw) {
    const initial = pw.site_name.charAt(0).toUpperCase();
    return `
        <div class="p-6 bg-white border-4 border-primary neo-shadow cursor-pointer hover:translate-x-[-2px] hover:translate-y-[-2px] hover:shadow-[6px_6px_0px_0px_rgba(26,26,26,1)] transition-all flex items-center justify-between group recent-item" data-id="${pw.id}">
            <div class="flex items-center space-x-4 pointer-events-none">
                <div class="w-12 h-12 border-4 border-primary bg-primary-container text-primary flex items-center justify-center font-headline text-xl font-black">${initial}</div>
                <div class="text-left">
                    <h4 class="font-headline font-black text-lg uppercase leading-tight truncate w-32 md:w-48">${escapeHtml(pw.site_name)}</h4>
                    <p class="text-[10px] font-mono text-on-surface-variant truncate w-32 md:w-48 mt-1">${escapeHtml(pw.username)}</p>
                </div>
            </div>
            <div class="flex flex-col items-end gap-2 flex-shrink-0 pointer-events-none">
                <span class="border-2 border-primary text-primary text-[9px] px-2 py-0.5 font-bold uppercase bg-white">${escapeHtml(pw.category)}</span>
            </div>
        </div>
    `;
}

// ==========================================================================
// Vault View Split-Pane Flow
// ==========================================================================
async function loadVault() {
    try {
        state.passwords = await api.getPasswords();
        $('#vault-total-count').textContent = `${state.passwords.length} TOTAL`;
        renderVaultList();
    } catch (err) {
        if (err.message === 'Vault is locked') { showView('unlock'); return; }
        toast('Failed to load credentials vault', 'error');
    }
}

function renderVaultList() {
    let filtered = state.passwords;

    if (state.activeFilter !== 'all') {
        filtered = filtered.filter(p => p.category === state.activeFilter);
    }

    if (state.searchQuery) {
        filtered = filtered.filter(p =>
            p.site_name.toLowerCase().includes(state.searchQuery) ||
            p.username.toLowerCase().includes(state.searchQuery) ||
            (p.notes || '').toLowerCase().includes(state.searchQuery)
        );
    }

    const list = $('#vault-list');

    if (filtered.length === 0) {
        list.innerHTML = `
            <div class="p-8 text-center bg-white text-on-surface-variant font-medium text-xs">
                No matching credentials.
            </div>
        `;
        // Clear active selection pane
        $('#vault-detail-content').classList.add('hidden');
        $('#vault-detail-empty').classList.remove('hidden');
        state.selectedId = null;
    } else {
        list.innerHTML = filtered.map(pw => renderPasswordItem(pw, pw.id === state.selectedId)).join('');
        
        // Bind row clicks
        list.querySelectorAll('.password-item').forEach(item => {
            item.onclick = () => {
                const id = parseInt(item.dataset.id);
                selectCredential(id);
            };
        });

        // Auto-select first row if none is active or selectedId is lost
        if (state.selectedId === null || !filtered.some(p => p.id === state.selectedId)) {
            selectCredential(filtered[0].id);
        } else {
            selectCredential(state.selectedId);
        }
    }
}

function renderPasswordItem(pw, isActive = false) {
    const initial = pw.site_name.charAt(0).toUpperCase();
    const activeClass = isActive ? 'bg-primary-container border-l-8 border-primary relative shadow-none' : 'hover:bg-surface-variant';
    const activeStar = isActive ? 'text-primary' : 'text-outline-variant';

    return `
        <div class="p-6 cursor-pointer group transition-all relative overflow-hidden password-item ${activeClass}" data-id="${pw.id}">
            <div class="flex items-start justify-between relative z-10 pointer-events-none">
                <div class="flex-grow">
                    <div class="flex items-center space-x-3">
                        <div class="w-10 h-10 border-2 border-primary flex items-center justify-center bg-primary text-white font-headline text-lg font-black">${initial}</div>
                        <div class="text-left">
                            <h3 class="font-headline font-extrabold text-sm leading-tight uppercase truncate w-32 md:w-40">${escapeHtml(pw.site_name)}</h3>
                            <p class="text-[10px] font-mono text-on-surface-variant truncate w-32 md:w-40 mt-1">${escapeHtml(pw.username)}</p>
                        </div>
                    </div>
                </div>
                <div class="flex flex-col items-end justify-between h-10 flex-shrink-0">
                    <span class="material-symbols-outlined ${activeStar} text-base" style="font-variation-settings: 'FILL' 1;">star</span>
                    <span class="border border-primary text-primary text-[8px] px-1.5 py-0.5 font-bold uppercase tracking-widest bg-white mt-2">${escapeHtml(pw.category)}</span>
                </div>
            </div>
        </div>
    `;
}

function selectCredential(id) {
    state.selectedId = id;
    const pw = state.passwords.find(p => p.id === id);
    if (!pw) return;

    // Highlight active list row
    $$('.password-item').forEach(item => {
        const itemId = parseInt(item.dataset.id);
        if (itemId === id) {
            item.className = 'p-6 cursor-pointer group transition-all relative overflow-hidden password-item bg-primary-container border-l-8 border-primary shadow-none';
            const star = item.querySelector('.material-symbols-outlined');
            if (star) star.className = 'material-symbols-outlined text-primary text-base';
        } else {
            item.className = 'p-6 cursor-pointer group transition-all relative overflow-hidden password-item hover:bg-surface-variant';
            const star = item.querySelector('.material-symbols-outlined');
            if (star) star.className = 'material-symbols-outlined text-outline-variant text-base';
        }
    });

    // Populate Right details pane elements
    const initial = pw.site_name.charAt(0).toUpperCase();
    $('#detail-site-icon').textContent = initial;
    $('#detail-site-name').textContent = pw.site_name;
    $('#detail-category-badge').textContent = pw.category;
    $('#detail-created-at').textContent = `CREATED: ${pw.created_at ? pw.created_at.slice(0, 10).replace(/-/g, '_') : 'RECENT'}`;
    $('#detail-username-val').textContent = pw.username;
    
    // Default secret mask
    $('#detail-password-val').textContent = '••••••••••••••••';
    $('#detail-toggle-pass-icon').textContent = 'visibility';
    $('#detail-url-val').textContent = pw.site_url || 'NO RESOURCE URL';
    $('#detail-notes-val').textContent = pw.notes || 'No secure notes saved for this credential.';

    // Strength audit visualization
    api.analyze(pw.password).then(analysis => {
        const rating = $('#detail-strength-rating');
        const bar = $('#detail-strength-bar');
        const entropy = $('#detail-entropy-val');
        const attr = getStrengthAttr(analysis.score);

        if (rating) { rating.textContent = analysis.rating; rating.setAttribute('data-score', attr); }
        if (bar) { bar.setAttribute('data-score', attr); bar.style.width = `${analysis.score}%`; }
        if (entropy) { entropy.textContent = `${analysis.entropy} bits / Strength Score: ${analysis.score}`; }
    }).catch(() => {});

    // Bind action shortcuts
    $('#btn-detail-copy-username').onclick = () => {
        navigator.clipboard.writeText(pw.username);
        toast('Username copied!', 'success');
    };

    $('#btn-detail-toggle-password').onclick = () => {
        const passText = $('#detail-password-val');
        const icon = $('#detail-toggle-pass-icon');
        if (passText.textContent === '••••••••••••••••') {
            passText.textContent = pw.password;
            icon.textContent = 'visibility_off';
        } else {
            passText.textContent = '••••••••••••••••';
            icon.textContent = 'visibility';
        }
    };

    $('#btn-detail-copy-password').onclick = () => {
        navigator.clipboard.writeText(pw.password);
        toast('Password copied!', 'success');
    };

    $('#btn-detail-open-url').onclick = () => {
        if (pw.site_url) {
            window.open(pw.site_url, '_blank');
        } else {
            toast('No URL resource saved', 'info');
        }
    };

    $('#btn-detail-edit').onclick = () => openPasswordModal(pw);

    $('#btn-detail-delete').onclick = () => {
        state.deleteId = pw.id;
        $('#modal-confirm').classList.add('active');
    };

    $('#vault-detail-empty').classList.add('hidden');
    $('#vault-detail-content').classList.remove('hidden');
}

// ==========================================================================
// Unified Modal (Add New / Edit Credential)
// ==========================================================================
function openPasswordModal(pw) {
    const title = $('#modal-title');
    const saveBtnText = $('#modal-save-btn .btn-text');

    if (pw) {
        // --- Edit Mode ---
        state.editingId = pw.id;
        title.textContent = 'Edit Credential';
        saveBtnText.textContent = 'Update Credential';

        $('#pw-edit-id').value = pw.id;
        $('#pw-site').value = pw.site_name;
        $('#pw-url').value = pw.site_url || '';
        $('#pw-username').value = pw.username;
        $('#pw-password').value = pw.password;
        $('#pw-password').type = 'password';
        $('#pw-category').value = pw.category;
        $('#pw-notes').value = pw.notes || '';
        $('#gen-modal-output').value = '';
        $('#gen-modal-length').value = 16;
        $('#gen-modal-length-val').textContent = 16;

        updateStrengthUI('pw', { score: 0, rating: 'EMPTY', entropy: 0 });
        $('#pw-password').dispatchEvent(new Event('input'));
    } else {
        // --- Create Mode ---
        state.editingId = null;
        title.textContent = 'New Credential';
        saveBtnText.textContent = 'Save to Vault';

        $('#pw-edit-id').value = '';
        $('#pw-site').value = '';
        $('#pw-url').value = '';
        $('#pw-username').value = '';
        $('#pw-password').value = '';
        $('#pw-password').type = 'password';
        $('#pw-category').value = 'General';
        $('#pw-notes').value = '';
        $('#gen-modal-output').value = '';
        $('#gen-modal-length').value = 16;
        $('#gen-modal-length-val').textContent = 16;

        // Reset toggles icon
        const toggIcon = document.querySelector('.password-toggle[data-target="pw-password"] .material-symbols-outlined');
        if (toggIcon) toggIcon.textContent = 'visibility';

        updateStrengthUI('pw', { score: 0, rating: 'EMPTY', entropy: 0 });
    }

    $('#modal-password').classList.add('active');
}

function closePasswordModal() {
    $('#modal-password').classList.remove('active');
    state.editingId = null;
}

async function handleSaveEditPassword() {
    const btn = $('#modal-save-btn');
    const site = $('#pw-site').value.trim();
    const url = $('#pw-url').value.trim();
    const username = $('#pw-username').value.trim();
    const password = $('#pw-password').value.trim();
    const category = $('#pw-category').value;
    const notes = $('#pw-notes').value.trim();

    if (!site || !username || !password) {
        toast('Site, Username, and Password are required!', 'error');
        return;
    }

    btn.disabled = true;

    try {
        if (state.editingId !== null) {
            // Update Existing
            await api.updatePassword(state.editingId, { site_name: site, site_url: url, username, password, category, notes });
            toast('Credential updated successfully!', 'success');
        } else {
            // Save New
            const res = await api.addPassword({ site_name: site, site_url: url, username, password, category, notes });
            toast('Credential saved to vault container!', 'success');
            state.selectedId = res.id; // Auto-select new row
        }
        
        closePasswordModal();
        if (state.activeTab === 'vault') loadVault();
        else if (state.activeTab === 'dashboard') loadDashboard();
    } catch (err) {
        toast(err.message, 'error');
    } finally {
        btn.disabled = false;
    }
}

// ==========================================================================
// Delete Confirmation Handler
// ==========================================================================
async function handleConfirmDelete() {
    if (!state.deleteId) return;
    try {
        await api.deletePassword(state.deleteId);
        toast('Credential permanently deleted', 'success');
        $('#modal-confirm').classList.remove('active');
        state.deleteId = null;
        state.selectedId = null; // Clear selections
        if (state.activeTab === 'vault') loadVault();
        else if (state.activeTab === 'dashboard') loadDashboard();
    } catch (err) {
        toast(err.message, 'error');
    }
}

// ==========================================================================
// Standalone Custom Generator Tab
// ==========================================================================
async function handleGenerateView() {
    const length = parseInt($('#gen-view-length').value);
    const opts = {
        length,
        use_upper:   $('#gen-view-upper').classList.contains('active'),
        use_lower:   $('#gen-view-lower').classList.contains('active'),
        use_digits:  $('#gen-view-digits').classList.contains('active'),
        use_symbols: $('#gen-view-symbols').classList.contains('active'),
    };

    // Keep at least one active option
    if (!opts.use_upper && !opts.use_lower && !opts.use_digits && !opts.use_symbols) {
        opts.use_lower = true;
        const btnLower = $('#gen-view-lower');
        btnLower.classList.add('active', 'bg-primary-container');
        btnLower.classList.remove('grayscale', 'opacity-50', 'bg-surface-variant');
    }

    try {
        const data = await api.generate(opts);
        $('#gen-view-output').textContent = data.password;
        
        // Update stand-alone strength statistics cards
        const rating = $('#gen-view-strength-rating');
        const bar = $('#gen-view-strength-bar');
        const entropyText = $('#gen-view-strength-entropy');
        const textLabel = $('#gen-view-strength-text');
        
        if (rating) rating.textContent = data.analysis.score;
        if (entropyText) entropyText.textContent = `${data.analysis.entropy} bits`;
        if (textLabel) textLabel.textContent = data.analysis.rating;
        if (bar) {
            const attr = getStrengthAttr(data.analysis.score);
            bar.setAttribute('data-score', attr);
            bar.style.width = `${data.analysis.score}%`;
        }
    } catch (err) {
        toast('Cryptographic generation failed', 'error');
    }
}

// ==========================================================================
// Standalone Strength Analyzer Tab
// ==========================================================================
async function handleAnalyze(password) {
    const resultEl = $('#analyzer-result');

    if (!password || password.length === 0) {
        resultEl.classList.add('hidden');
        return;
    }

    try {
        const analysis = await api.analyze(password);
        resultEl.classList.remove('hidden');

        // Score visual ring dashboard KPI
        const circle = $('#analyzer-score-circle');
        const circumference = 2 * Math.PI * 52; // r=52
        const offset = circumference - (analysis.score / 100) * circumference;
        circle.style.strokeDasharray = `${circumference}`;
        circle.style.strokeDashoffset = `${offset}`;

        // Ring dynamic coloring rules
        const attr = getStrengthAttr(analysis.score);
        const colorMap = {
            vweak: '#e63b2e', weak: '#e63b2e', fair: '#ffcc00', strong: '#0055ff', vstrong: '#10b981'
        };
        circle.style.stroke = colorMap[attr] || '#1a1a1a';

        // Update score indicators
        $('#analyzer-score-num').textContent = analysis.score;
        $('#analyzer-score-num').style.color = colorMap[attr];

        const ratingEl = $('#analyzer-rating-text');
        ratingEl.textContent = analysis.rating;
        ratingEl.style.color = colorMap[attr];

        $('#analyzer-entropy-text').textContent = `Entropy: ${analysis.entropy} bits / Cryptographic strength`;

        const bar = $('#analyzer-strength-bar');
        if (bar) {
            bar.setAttribute('data-score', attr);
            bar.style.width = `${analysis.score}%`;
        }

        // Output checkboxes
        const checksEl = $('#analyzer-checks');
        const checkItems = [
            { key: 'length',    label: '8+ Characters',     icon: '📏' },
            { key: 'uppercase', label: 'Uppercase (A-Z)',    icon: '🔠' },
            { key: 'lowercase', label: 'Lowercase (a-z)',    icon: '🔡' },
            { key: 'digits',    label: 'Numbers (0-9)',      icon: '🔢' },
            { key: 'symbols',   label: 'Symbols (!@#)',      icon: '🔣' },
            { key: 'no_common', label: 'Not Common',         icon: '🛡️' },
        ];
        checksEl.innerHTML = checkItems.map(c => {
            const passed = analysis.checks[c.key];
            return `
                <div class="check-item ${passed ? 'pass' : 'fail'} flex items-center gap-1.5 border border-primary p-2 bg-white">
                    <span class="check-icon flex items-center justify-center font-black">${passed ? '✓' : '✗'}</span>
                    <span class="check-label text-[10px] truncate">${c.label}</span>
                </div>
            `;
        }).join('');

        // Warnings list feedback alerts
        const fbEl = $('#analyzer-feedback-list');
        fbEl.innerHTML = analysis.feedback.map(f => {
            const isGood = f.includes('Excellent');
            return `<div class="p-3 border-2 border-primary ${isGood ? 'bg-primary-container' : 'bg-secondary-container'} text-[10px] font-bold uppercase tracking-wide flex items-center gap-2">
                <span class="material-symbols-outlined text-sm font-black">${isGood ? 'check' : 'warning'}</span>
                <span>${f}</span>
            </div>`;
        }).join('');

    } catch (err) {
        toast('Analysis calculation failed', 'error');
    }
}

// ==========================================================================
// Security Rotating Form Flow
// ==========================================================================
function resetSecurityForm() {
    $('#security-current-password').value = '';
    $('#security-new-password').value = '';
    $('#security-confirm-password').value = '';
    $('#security-current-password').type = 'password';
    $('#security-new-password').type = 'password';
    $('#security-confirm-password').type = 'password';
    
    // reset eye icon togglers
    $$('.password-toggle[data-target^="security-"] .material-symbols-outlined').forEach(icon => icon.textContent = 'visibility');
    
    $('#security-error').classList.add('hidden');
    updateStrengthUI('security', { score: 0, rating: 'EMPTY', entropy: 0, feedback: [] });
}

async function handleSecurityChange(e) {
    e.preventDefault();
    const btn = $('#security-save-btn');
    const errEl = $('#security-error');
    const currentPw = $('#security-current-password').value;
    const newPw = $('#security-new-password').value;
    const confirmPw = $('#security-confirm-password').value;

    errEl.classList.add('hidden');

    if (newPw !== confirmPw) {
        errEl.textContent = 'Change Failure: New passwords do not match';
        errEl.classList.remove('hidden');
        return;
    }

    if (currentPw === newPw) {
        errEl.textContent = 'Change Failure: New password must be different from current';
        errEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;

    try {
        await api.changeMaster(currentPw, newPw);
        toast('Vault password changed and container successfully re-encrypted!', 'success');
        resetSecurityForm();
        
        // Auto-redirect to dashboard
        setTimeout(() => showTab('dashboard'), 1500);
    } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
        toast(err.message, 'error');
    } finally {
        btn.disabled = false;
    }
}

// ==========================================================================
// HTML Sanitization Helpers
// ==========================================================================
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
