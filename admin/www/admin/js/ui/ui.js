/**
 * UI Module - Specific renderers and state management for lists, config, and settings
 */
import * as helpers from './helpers.js';

export const renderAPIKeys = (tokens, allTokens, apiKeysListContainer, editAPIKey, deleteAPIKey) => {
    if (!apiKeysListContainer) return;
    apiKeysListContainer.innerHTML = '';
    
    tokens.forEach(k => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${helpers.escapeHTML(k.name)}</td>
            <td>${(k.permissions || []).map(p => `<span class="badge secondary">${helpers.escapeHTML(p)}</span>`).join(' ')}</td>
            <td>${new Date(k.created_at).toLocaleDateString()}</td>
            <td>${!k.last_used || k.last_used === '0001-01-01T00:00:00Z' ? 'Never' : new Date(k.last_used).toLocaleString()}</td>
            <td>
                <button class="btn btn-sm secondary edit-key-btn" data-id="${k.id}">Edit</button>
                <button class="btn btn-sm danger delete-key-btn" data-id="${k.id}">Delete</button>
            </td>
        `;
        apiKeysListContainer.appendChild(tr);
    });

    // Add listeners using delegation or directly (here directly for simplicity in a port)
    apiKeysListContainer.querySelectorAll('.edit-key-btn').forEach(btn => {
        btn.onclick = () => editAPIKey(btn.getAttribute('data-id'));
    });
    apiKeysListContainer.querySelectorAll('.delete-key-btn').forEach(btn => {
        btn.onclick = () => deleteAPIKey(btn.getAttribute('data-id'));
    });
};

export const createListItem = (list, index, type, removeList, toggleList, openDetails) => {
    const item = document.createElement('div');
    item.className = 'list-item';
    item.setAttribute('data-index', index);
    item.setAttribute('data-type', type);
    
    const statusClass = list.enabled ? 'enabled' : 'disabled';
    const statusText = list.enabled ? 'Active' : 'Disabled';
    
    item.innerHTML = `
        <div class="list-info">
            <div class="list-status-pill ${statusClass}">${statusText}</div>
            <div class="list-name">${helpers.escapeHTML(list.name)}</div>
            <div class="list-meta">${(list.entries || 0).toLocaleString()} entries • Updated ${helpers.formatDate(list.updated_at)}</div>
        </div>
        <div class="list-actions">
            <button class="btn btn-sm secondary toggle-list-btn">${list.enabled ? 'Disable' : 'Enable'}</button>
            <button class="btn btn-sm danger remove-list-btn"><i class="fas fa-trash"></i></button>
        </div>
    `;

    item.querySelector('.toggle-list-btn').onclick = (e) => {
        e.stopPropagation();
        toggleList(type, index);
    };
    item.querySelector('.remove-list-btn').onclick = (e) => {
        e.stopPropagation();
        removeList(type, index);
    };
    item.onclick = () => openDetails(list);

    return item;
};
