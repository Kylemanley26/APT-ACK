# MITRE ATT&CK Matrix Modal - UX Guide

## Overview

The MITRE matrix modal provides visual context when clicking technique badges, showing where techniques fit in the ATT&CK framework before filtering threat intel.

## User Experience Flow

### Before (Old UX)
```
Click technique badge → Redirects to feeds page → See filtered results
Problem: No context about what you're filtering by
```

### After (New UX)
```
Click technique badge → Modal opens with matrix → See technique highlighted → Click "View Feeds" → See filtered results
Benefit: Visual context of technique within ATT&CK framework
```

## Features

### 1. Visual Matrix Display
- **7x5 grid layout** matching MITRE's official matrix
- **Color coding:**
  - Yellow: Selected technique
  - Purple: Techniques detected in your feeds
  - Gray: Techniques not detected
- **Tactic columns** highlighted when selected
- **Scrollable** for all 80+ techniques

### 2. Interactive Elements
- **Click any technique** to view details
- **Hover** for technique names
- **Count badges** show number of related threat intel items
- **"View X Related Feeds"** button filters directly

### 3. Access Points
- Click any purple technique badge on feed items
- Click "View Matrix" button on dashboard/feeds page
- Click ATT&CK stat card on dashboard

## Visual Layout

```
┌─────────────────────────────────────────────────────────────────┐
│ MITRE ATT&CK Enterprise Matrix                            [X]  │
│ T1566: Phishing (Initial Access) [23 items]                    │
├─────────────────────────────────────────────────────────────────┤
│ ┌──────────┬──────────┬──────────┬──────────┬──────────┐       │
│ │ Initial  │Execution │Persistence│ Privile │ Defense  │       │
│ │ Access   │          │           │ Escal   │ Evasion  │       │
│ ├──────────┼──────────┼──────────┼──────────┼──────────┤       │
│ │[T1566] 23│ T1059 45 │ T1547 12 │ T1068 5  │ T1027 34 │       │
│ │ Phishing │ Scripts  │ Autostart│ Exploit  │ Obfusc   │       │
│ │          │          │          │          │          │       │
│ │ T1190 12 │ T1204 18 │ T1543 8  │ T1548 3  │ T1562 28 │       │
│ │ Exploit  │ User Exe │ Service  │ Abuse    │ Impair   │       │
│ └──────────┴──────────┴──────────┴──────────┴──────────┘       │
│                                                                  │
│ [■ Selected] [■ Detected] [■ Not Detected]  [View 23 Feeds]   │
└─────────────────────────────────────────────────────────────────┘
```

## Implementation

### Files Updated

**1. mitre_matrix_modal.html** (New Component)
- Reusable modal template
- Include in any page: `{% include 'mitre_matrix_modal.html' %}`

**2. feeds_complete.html** (Updated Feeds Page)
- Technique badges open modal instead of redirecting
- Active filter banner shows selected technique
- Clear filter buttons
- "View Matrix" button in results section

**3. index_with_modal.html** (Updated Dashboard)
- Technique badges open modal
- Clickable ATT&CK stat card
- "View Matrix" button in feed section

### Template Placement

```
web/templates/
├── base.html
├── index.html  → Replace with index_with_modal.html
├── feeds.html  → Replace with feeds_complete.html
└── mitre_matrix_modal.html  → NEW component file
```

### JavaScript Integration

Each page needs these Alpine.js properties:

```javascript
data() {
    return {
        // MITRE Modal state
        mitreModal: {
            show: false,
            technique: null
        },
        
        // MITRE Matrix data
        mitreMatrix: {
            tactics: ['Initial Access', 'Execution', ...],
            techniques: {} // Loaded from API
        },
        
        // Methods
        showMitreModal(technique) {
            this.mitreModal.technique = technique;
            this.mitreModal.show = true;
            if (!this.mitreMatrix.techniques) this.loadMitreMatrix();
        },
        
        loadMitreMatrix() {
            fetch('/api/techniques').then(r => r.json()).then(data => {
                this.mitreMatrix.techniques = data;
            });
        },
        
        getTacticTechniques(tactic) {
            return this.mitreMatrix.techniques[tactic] || [];
        },
        
        viewTechnique(technique) {
            this.mitreModal.technique = technique;
        }
    }
}
```

## User Interactions

### Scenario 1: Exploring Techniques
```
User sees: "T1566" badge on feed item
User clicks: Purple technique badge
Modal opens: Shows full matrix with T1566 highlighted in yellow
User sees: T1566 is in "Initial Access" tactic
User sees: "23 items" related to this technique
User clicks: "View 23 Related Feeds"
Result: Redirects to /feeds?technique=t1566
```

### Scenario 2: Browsing Matrix
```
User clicks: "View Matrix" button
Modal opens: Shows full matrix
User clicks: T1486 (ransomware)
Technique updates: T1486 highlighted
User sees: "45 items" with this technique
User clicks: "View 45 Related Feeds"
Result: Filters to ransomware-related intel
```

### Scenario 3: Understanding Context
```
User filtering: Currently viewing T1003 (credential dumping)
User clicks: Another T1003 badge on different item
Modal opens: Shows T1003 in "Credential Access" tactic
User sees: Related techniques nearby (T1110, T1555)
User clicks: T1110 to compare brute force intel
Result: Switches filter to T1110
```

## Benefits

### For Security Analysts
- **Visual context** of techniques within kill chain
- **Quick comparison** of related techniques
- **Coverage visibility** - see which techniques appear in feeds
- **Exploration** - discover related techniques

### For Threat Hunting
- **Tactic-based** hunting (all Initial Access techniques)
- **Technique relationships** visible in grid layout
- **Heat map** shows most common techniques
- **Direct filtering** to relevant threat intel

### For Reporting
- **Screenshot matrix** with highlighted techniques
- **Coverage metrics** visible (purple vs gray)
- **Frequency data** in count badges
- **Professional visualization** for stakeholders

## Keyboard Shortcuts

- **ESC** - Close modal
- **Click outside** - Close modal
- **Click technique** - Select and view details
- **Click "View Feeds"** - Filter and close modal

## Mobile Responsiveness

- Modal adapts to screen size
- Scrollable matrix on small screens
- Touch-friendly technique buttons
- Swipeable on mobile devices

## Performance

- **Lazy loading** - Matrix data loaded only when modal opens
- **Cached** - Data persists after first load
- **Fast rendering** - Only top 12 techniques per tactic shown
- **No API calls** on subsequent opens

## Customization Options

### Show More Techniques Per Tactic
```javascript
getTacticTechniques(tactic) {
    return this.mitreMatrix.techniques[tactic].slice(0, 20); // Show 20 instead of 12
}
```

### Add Technique Descriptions
```javascript
<div class="text-xs mt-0.5" x-text="technique.description"></div>
```

### Auto-open on Page Load
```javascript
init() {
    const urlTechnique = new URLSearchParams(location.search).get('technique');
    if (urlTechnique) {
        this.showMitreModal({ id: urlTechnique.toUpperCase() });
    }
}
```

## Troubleshooting

**Modal doesn't open:**
- Check Alpine.js loaded
- Verify `mitreModal.show` property exists
- Check browser console for errors

**Techniques not displaying:**
- Verify `/api/techniques` returns data
- Check `loadMitreMatrix()` called
- Ensure MITRE mapping ran on feeds

**Wrong technique highlighted:**
- Check technique ID case (should be uppercase)
- Verify `mitreModal.technique.id` matches

**Styling issues:**
- Tailwind CDN loaded?
- Check `[x-cloak]` CSS present
- Verify z-index on modal (z-50)

## Testing Checklist

- [ ] Click technique badge opens modal
- [ ] Selected technique highlighted in yellow
- [ ] Detected techniques show in purple
- [ ] Tactic column highlighted
- [ ] Count badges display correctly
- [ ] "View X Feeds" button works
- [ ] Modal closes on ESC
- [ ] Modal closes on backdrop click
- [ ] Clicking technique updates selection
- [ ] Matrix loads from API
- [ ] Responsive on mobile
- [ ] Works on dashboard
- [ ] Works on feeds page
- [ ] Works on techniques page

## Future Enhancements

- **Sub-techniques** (T1566.001, T1566.002)
- **MITRE Navigator export** (JSON layer file)
- **Technique search** within modal
- **Animated transitions** between techniques
- **Keyboard navigation** (arrow keys)
- **Procedure examples** from threat intel
- **Related IOCs** preview
- **Technique timeline** (when first/last seen)
