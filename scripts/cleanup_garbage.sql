-- APT-ACK Cleanup Script
-- Run via: railway run psql $DATABASE_URL -f scripts/cleanup_garbage.sql
-- Or paste into: railway run psql $DATABASE_URL

-- ============================================================================
-- 1. DELETE GARBAGE IOCs (filenames mistaken as domains)
-- ============================================================================

DELETE FROM iocs WHERE ioc_type = 'domain' AND (
    -- File extensions
    value ILIKE '%.exe' OR
    value ILIKE '%.dll' OR
    value ILIKE '%.sys' OR
    value ILIKE '%.txt' OR
    value ILIKE '%.log' OR
    value ILIKE '%.bat' OR
    value ILIKE '%.cmd' OR
    value ILIKE '%.ps1' OR
    value ILIKE '%.vbs' OR
    value ILIKE '%.js' OR
    value ILIKE '%.msi' OR
    value ILIKE '%.doc' OR
    value ILIKE '%.docx' OR
    value ILIKE '%.xls' OR
    value ILIKE '%.xlsx' OR
    value ILIKE '%.pdf' OR
    value ILIKE '%.zip' OR
    value ILIKE '%.rar' OR
    value ILIKE '%.7z' OR
    value ILIKE '%.tar' OR
    value ILIKE '%.gz' OR
    value ILIKE '%.iso' OR
    value ILIKE '%.img' OR
    value ILIKE '%.jpg' OR
    value ILIKE '%.png' OR
    value ILIKE '%.gif' OR
    value ILIKE '%.mp3' OR
    value ILIKE '%.mp4' OR
    value ILIKE '%.py' OR
    value ILIKE '%.c' OR
    value ILIKE '%.cpp' OR
    value ILIKE '%.h' OR
    value ILIKE '%.java' OR
    value ILIKE '%.xml' OR
    value ILIKE '%.json' OR
    value ILIKE '%.yaml' OR
    value ILIKE '%.yml' OR
    value ILIKE '%.ini' OR
    value ILIKE '%.cfg' OR
    value ILIKE '%.conf' OR
    value ILIKE '%.config' OR
    value ILIKE '%.html' OR
    value ILIKE '%.htm' OR
    value ILIKE '%.css' OR
    value ILIKE '%.csv' OR
    value ILIKE '%.sql' OR
    value ILIKE '%.db' OR
    value ILIKE '%.bak' OR
    value ILIKE '%.tmp' OR
    value ILIKE '%.dat' OR
    value ILIKE '%.bin' OR
    value ILIKE '%.lnk'
);

-- ============================================================================
-- 2. DELETE VX-UNDERGROUND FEED ITEMS
-- ============================================================================

-- First delete IOCs associated with VX-Underground items
DELETE FROM iocs WHERE feed_item_id IN (
    SELECT id FROM feed_items WHERE source_name LIKE 'VX-Underground%'
);

-- Delete tag associations for VX-Underground items
DELETE FROM feed_item_tags WHERE feed_item_id IN (
    SELECT id FROM feed_items WHERE source_name LIKE 'VX-Underground%'
);

-- Delete the feed items themselves
DELETE FROM feed_items WHERE source_name LIKE 'VX-Underground%';

-- ============================================================================
-- 3. DELETE GARBAGE FEED ITEMS (Git commit messages)
-- ============================================================================

-- Delete IOCs from garbage items first
DELETE FROM iocs WHERE feed_item_id IN (
    SELECT id FROM feed_items WHERE 
        title LIKE 'Add files via upload%' OR
        title LIKE 'Update README%' OR
        title LIKE 'Update %.c' OR
        title LIKE 'Update %.cpp' OR
        title LIKE 'Update %.py' OR
        title LIKE 'Delete %.c' OR
        title LIKE 'Delete %.cpp' OR
        title LIKE 'Delete %.py' OR
        title LIKE 'Create %.7z' OR
        title LIKE 'Merge pull request%' OR
        title = 'new' OR
        title = 'new...' OR
        title = 'Upload' OR
        title = 'Upload...' OR
        title = 'updates' OR
        title = 'updates...' OR
        title = 'rename' OR
        title = 'rename...' OR
        title = 'new additions' OR
        title = 'new additions...' OR
        title = 'New family' OR
        title = 'New family...' OR
        LENGTH(title) < 10
);

-- Delete tag associations
DELETE FROM feed_item_tags WHERE feed_item_id IN (
    SELECT id FROM feed_items WHERE 
        title LIKE 'Add files via upload%' OR
        title LIKE 'Update README%' OR
        title LIKE 'Update %.c' OR
        title LIKE 'Update %.cpp' OR
        title LIKE 'Update %.py' OR
        title LIKE 'Delete %.c' OR
        title LIKE 'Delete %.cpp' OR
        title LIKE 'Delete %.py' OR
        title LIKE 'Create %.7z' OR
        title LIKE 'Merge pull request%' OR
        title = 'new' OR
        title = 'new...' OR
        title = 'Upload' OR
        title = 'Upload...' OR
        title = 'updates' OR
        title = 'updates...' OR
        title = 'rename' OR
        title = 'rename...' OR
        title = 'new additions' OR
        title = 'new additions...' OR
        title = 'New family' OR
        title = 'New family...' OR
        LENGTH(title) < 10
);

-- Delete the garbage feed items
DELETE FROM feed_items WHERE 
    title LIKE 'Add files via upload%' OR
    title LIKE 'Update README%' OR
    title LIKE 'Update %.c' OR
    title LIKE 'Update %.cpp' OR
    title LIKE 'Update %.py' OR
    title LIKE 'Delete %.c' OR
    title LIKE 'Delete %.cpp' OR
    title LIKE 'Delete %.py' OR
    title LIKE 'Create %.7z' OR
    title LIKE 'Merge pull request%' OR
    title = 'new' OR
    title = 'new...' OR
    title = 'Upload' OR
    title = 'Upload...' OR
    title = 'updates' OR
    title = 'updates...' OR
    title = 'rename' OR
    title = 'rename...' OR
    title = 'new additions' OR
    title = 'new additions...' OR
    title = 'New family' OR
    title = 'New family...' OR
    LENGTH(title) < 10;

-- ============================================================================
-- 4. SHOW CLEANUP RESULTS
-- ============================================================================

SELECT 'Remaining feed items:' as info, COUNT(*) as count FROM feed_items;
SELECT 'Remaining IOCs:' as info, COUNT(*) as count FROM iocs;
SELECT 'Items by source:' as info;
SELECT source_name, COUNT(*) as count FROM feed_items GROUP BY source_name ORDER BY count DESC;
