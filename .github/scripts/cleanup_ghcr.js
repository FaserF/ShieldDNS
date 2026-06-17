#!/usr/bin/env node
// Cleans up old ShieldDNS images from GHCR:
//   - All stable releases (vX.Y.Z / latest) are KEPT forever
//   - Only the newest beta (vX.Y.ZbN) is kept
//   - Only the newest dev (vX.Y.Z-devN) is kept
//   - Untagged manifests not linked to a kept release are deleted
const { execSync } = require('child_process');

const PACKAGE_NAME = 'shielddns';

function runGh(command) {
    try {
        return execSync(`gh ${command}`, { encoding: 'utf8' }).trim();
    } catch (e) {
        console.error(`Failed to run gh command: ${command}`, e.message);
        return null;
    }
}

async function main() {
    const owner = process.env.GITHUB_REPOSITORY_OWNER;
    if (!owner) {
        console.error('GITHUB_REPOSITORY_OWNER environment variable is required.');
        process.exit(1);
    }
    const ownerLower = owner.toLowerCase();

    console.log(`Checking user type for ${ownerLower}...`);
    const userJson = runGh(`api users/${ownerLower}`);
    if (!userJson) {
        console.error('Could not fetch user info from GitHub API.');
        process.exit(1);
    }
    const userType = JSON.parse(userJson).type;
    const endpointPrefix = userType === 'Organization' ? `orgs/${ownerLower}` : `users/${ownerLower}`;

    console.log(`Listing versions for ghcr.io/${ownerLower}/${PACKAGE_NAME}...`);
    const versionsJson = runGh(`api ${endpointPrefix}/packages/container/${PACKAGE_NAME}/versions --paginate`);
    if (!versionsJson) {
        console.error('Could not fetch package versions.');
        process.exit(1);
    }

    let versions = [];
    try {
        const trimmed = versionsJson.trim();
        if (trimmed.startsWith('[')) {
            const parts = trimmed.split(/\r?\n\r?\n|\r?\n(?=\[)/);
            for (const part of parts) {
                if (part.trim()) {
                    versions = versions.concat(JSON.parse(part));
                }
            }
        } else {
            versions = JSON.parse(trimmed);
        }
    } catch (err) {
        console.error('Failed to parse package versions JSON:', err.message);
        process.exit(1);
    }

    console.log(`Found ${versions.length} package version(s).`);

    const isStableTag = (tag) => tag === 'latest' || /^\d+\.\d+\.\d+$/.test(tag) || /^v\d+\.\d+\.\d+$/.test(tag);
    const isBetaTag   = (tag) => tag === 'beta'   || /^v?\d+\.\d+\.\d+b\d+$/.test(tag);
    const isDevTag    = (tag) => tag === 'dev'     || tag.includes('dev');

    const stableVersions   = [];
    const betaVersions     = [];
    const devVersions      = [];
    const untaggedVersions = [];

    for (const v of versions) {
        const tags = v.metadata?.container?.tags || [];
        if (tags.length === 0) { untaggedVersions.push(v); continue; }
        if (tags.some(isStableTag)) { stableVersions.push(v); continue; }
        if (tags.some(isBetaTag))   { betaVersions.push(v);   continue; }
        if (tags.some(isDevTag))    { devVersions.push(v);    continue; }
        untaggedVersions.push(v);
    }

    const sortByNewest = (a, b) => new Date(b.created_at) - new Date(a.created_at);

    const keptVersions = [...stableVersions];
    if (betaVersions.length > 0) { betaVersions.sort(sortByNewest); keptVersions.push(betaVersions[0]); }
    if (devVersions.length > 0)  { devVersions.sort(sortByNewest);  keptVersions.push(devVersions[0]);  }
    const keptTimes = keptVersions.map(v => new Date(v.created_at).getTime());

    const isProtectedUntagged = (v) => {
        const time = new Date(v.created_at).getTime();
        return keptTimes.some(kt => Math.abs(kt - time) < 600000);
    };

    const toDeleteIds = new Set();

    for (const v of untaggedVersions) {
        if (!isProtectedUntagged(v)) {
            toDeleteIds.add(v.id);
        } else {
            console.log(`Protecting untagged child manifest: ${v.id} (${v.created_at})`);
        }
    }

    // Keep only newest beta/dev, delete older ones
    for (let i = 1; i < betaVersions.length; i++) toDeleteIds.add(betaVersions[i].id);
    for (let i = 1; i < devVersions.length;  i++) toDeleteIds.add(devVersions[i].id);

    console.log(`Stable versions kept (never deleted): ${stableVersions.length}`);
    for (const v of stableVersions) {
        console.log(` - ID: ${v.id} (${v.metadata?.container?.tags?.join(', ')})`);
    }
    console.log(`Total versions marked for deletion: ${toDeleteIds.size}`);

    for (const id of toDeleteIds) {
        const v = versions.find(item => item.id === id);
        const tagsDesc = v?.metadata?.container?.tags?.join(', ') || 'untagged';
        console.log(`Deleting version ${id} (${tagsDesc}) created at ${v?.created_at}...`);
        const res = runGh(`api --method DELETE ${endpointPrefix}/packages/container/${PACKAGE_NAME}/versions/${id}`);
        if (res !== null) {
            console.log(`Successfully deleted version ${id}.`);
        } else {
            console.error(`Failed to delete version ${id}.`);
        }
    }

    console.log('Cleanup process completed successfully.');
}

main().catch(err => {
    console.error('Cleanup script failed:', err);
    process.exit(1);
});
