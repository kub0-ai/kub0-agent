# Panel redesign—adopt the Omarchy panel grammar

*A design record from when the panel was called Vallum. It is kept as written;
what shipped is in the README and the changelog.*

Vallum's panel was built without reference to the panels it sits next to. Wifi,
Bluetooth, Tailscale and Agents all speak one visual grammar; Vallum speaks its
own. This maps the grammar and where Vallum has to move.

Reference sources, all under `/usr/share/omarchy/shell/`:
`plugins/panels/network/Panel.qml`, `plugins/panels/bluetooth/Panel.qml`,
`plugins/panels/tailscale/Panel.qml`, `plugins/agents/Panel.qml`.

---

## 1. The grammar

Every reference panel is the same seven lines:

```qml
KeyboardPanel {
  PanelKeyCatcher {
    Flickable {                 // ONE scroll. No tabs anywhere in the shell.
      Column {
        <header>                // title, details, controls at top-right
        PanelSeparator {}
        Column { PanelSectionHeader {}; <rows> }
        PanelSeparator {}
        Column { PanelSectionHeader {}; <rows> }
        PanelSeparator {}
        Column { PanelSectionHeader {}; <rows> }
```

Adoption is not incidental—it is unanimous, and the separator count is
identical across all four, which is what makes them feel like one product:

| panel | `PanelHero` | `PanelSectionHeader` | `PanelSeparator` | tabs |
|---|---|---|---|---|
| network | 0 (inline header) | 6 | 3 | 0 |
| bluetooth | 0 (inline header) | 2 | 3 | 0 |
| tailscale | 2 | 3 | 3 | 0 |
| agents | 1 | 4 | 3 | 0 |
| **vallum** | **0** | **0** | **1** | **5** |

Three separators ⇒ four visual groups is the house rhythm.

## 2. The header—exactly the shape you described

Two idioms, same anatomy. The newer one is a shared component,
`Ui/PanelHero.qml`, and its properties *are* the spec:

| property | role | your words |
|---|---|---|
| `title` | name, top-left | "Title at top" |
| `meta` | primary status line | "details (plan name, etc) right under" |
| `detail` | secondary status line | ″ |
| `trailingControl` | `Component`, pinned top-right | "on/off or settings at right top" |
| `iconComponent` | leading icon | |

The older inline idiom (network, bluetooth) hand-rolls the same thing:
`Item { Text /*title*/; RowLayout { Button; Button; ToggleSwitch } /*top-right*/;
Column { Text; Text } /*details under title*/ }`.

🔑 **Secondary actions are icon buttons in the trailing cluster, not tabs.**
network's cluster is `Button{iconText:"󰐲"; tooltipText:"Show QR code"} · Button ·
ToggleSwitch`, with the master toggle rightmost. That is where a settings gear
belongs.

## 3. Where Vallum diverged

> Kept in the past tense it was written in: this is the diagnosis that motivated
> the work, not current state. §4.2 and §5 record what actually shipped.

Structure at the time (`Panel.qml`, 2987 lines—larger than any reference panel):

```
Item
  Column { Column; Row }        // hand-rolled tab bar
  Item { Flickable; Item; Item; Flickable; Flickable }   // 5 tab bodies
  ConfirmDialog
  ConfirmDialog
```

Five tabs—Connections, Apps, Blocked, Activity, Settings—where the rest of
the shell has none. Three consequences:

1. **No status surface.** There is nowhere that says active / inactive / not
   installed / protected, because there is no header. Every other panel answers
   that question in its first two lines.
2. **Navigation nobody has learned.** A user arriving from Wifi or Bluetooth
   knows to scroll and read section headers. Vallum asks them to learn tabs.
3. **State hidden behind a click.** Tabs hide four fifths of the panel. Blocked
   apps—the thing the tool exists for—are invisible unless you go looking.

## 4. The reorganization

### 4.1 Header (new—this is also the Protection-status surface)

```qml
PanelHero {
  title: "Vallum"
  meta:   <posture>     // "Protected" / "Active" / "Inactive" / "Not installed"
  detail: <substrate>   // "connected · nft+cgroup · 47 connections"
  trailingControl: Component {
    RowLayout {
      Button { iconText: "󰒓"; tooltipText: "Settings" }   // was a tab
      ToggleSwitch { }                                     // master enforcement
    }
  }
}
```

`meta` must distinguish all four states the operator asked for—active,
inactive, not installed, and whether anything is actually protected right now.
Derive it from the helper's own `blockingReady` plus the live block count, never
from a UI flag: `tests/enforcement-selftest.sh` proves the kernel state and the
UI's belief can disagree.

### 4.2 Tabs → views—SHIPPED, and not as planned

The five tabs are gone. What replaced them is **two data views plus Settings**,
not the single scroll of three sections this section originally specified:

| today (tab) | became | why |
|---|---|---|
| Connections | folded into **Overview** | the map, the monitoring headline and the top-destination rows are one answer to "what is happening", not three |
| Activity | folded into **Overview** | already a property of a connection row, and searchable from the same `/` |
| Blocked | the **Apps** header itself | `appsHeaderText` is `"Apps  3 blocked of 41"`, so the count is on screen in both views |
| Apps | **Apps**, a `ListView` | the inventory is the only unbounded list |
| Settings | **trailing gear button** | matches network; not a peer of the data |

`root.panelView` is `"overview" | "apps" | "settings"`. The two data views are
switched by **clicking their own `PanelSectionHeader`**—both headers stay
visible, the inactive one at `opacity: 0.6`, so the switch is a label you can
already see rather than a control you have to learn. The gear sets
`"settings"` and stashes `viewBeforeSettings`, so leaving Settings returns you
to the view you came from. `Prefs.openingView()` decides which view opens,
including `"last"`.

🔑 **Why not one Flickable of three sections, as planned.** Apps is an
unbounded inventory. Putting it in the same `Flickable` as the map makes the
whole panel one unbounded scroll, and the map—the thing that orients
you—scrolls off the top as soon as the list is non-trivial. Apps keeps its own
internally-scrolling `ListView` and the panel never becomes a single long page.
The house rhythm is still honoured, just per view rather than across one column.

⚠️ So §3's three complaints are answered, but complaint 3 ("blocked apps are
invisible unless you go looking") is answered by putting the **count** in the
always-visible header, not by giving Blocked a section of its own.

### 4.3 Settings

Not a tab and not a separate panel—the gear in `trailingControl` swaps the
`Flickable`'s content in place, same `KeyboardPanel`. Keep `js/Prefs.js` and the
`FileView`-on-Service persistence exactly as shipped; only the entry
point moves.

## 5. Sequence—all four steps shipped

| step | state | note |
|---|---|---|
| 1. `PanelHero` + posture + master toggle | ✅ | `heroMeta` comes from `Health.heroPosture()`, pinned by `tests/test_hero_posture.qml` |
| 2. Delete the tab `Row` | ✅ | became two views, not one column—see §4.2 |
| 3. Settings behind the gear | ✅ | a third `panelView`, with `viewBeforeSettings` to get back |
| 4. Fold Activity into the connections view | ✅ | Overview, sharing the `/` search |

Step 1 did land independently and did answer the status request on its own, as
predicted.

### 5.1 What the redesign turned up that this document did not predict

Adopting the grammar exposed two defects that were invisible while the panel
was still tabs, and both are now part of the grammar:

- **Sections were prose, not data.** Settings read as a static menu because its
  facts were middot-joined sentences. They are now `FactRow` label/value pairs
  from `helperFacts()` / `endpointFacts()` / `fleetFacts()` / `keyboardFacts()`,
  and the section *headings* carry live state (`endpointHeading()`,
  `enforcementHeading()`, `fleetHeading()`) so a section answers its own
  question before you read its rows.
- **A fleet policy could only be rendered by its matcher.** `DenylistEntry` now
  carries a `name`—the org's own words for what a rule is *for*—with
  `label()` falling back to `"{verb} {target}"` and then `"Unnamed rule"`.
  ⚠️ The upstream half is still open: the daemon cannot reach "Block crypto
  miners" from `xmrig`, so the kub0 API has to send a purposeful `name`.

🔑 **The middot is not banned—it is the shell's own grammar for a compact
status line** (`agents` joins usage with it, `tailscale` does
`parts.join(" · ")`). `heroDetail` and `connSummary()` keep it because they
have no room for rows. The defect was middots standing in *for* rows, in a
place that had room.

### 5.2 Naming an unknown peer

The clue engine surfaces in the panel through `js/Peers.js`, whose rules are in
a module and not in `Panel.qml` because they decide how confident the UI
*sounds*—the part of the feature that can be wrong without looking wrong:

- Precedence: a human name beats a machine guess; a guess only speaks in the
  summary line when it is `certain` or `strong`.
- A `weak` clue is dropped from the summary and surfaces **only** in the
  expanded row, with its basis, phrased as a guess. A summary line has no room
  to say "probably", and a hunch in the same typeface as a fact is how a naming
  feature starts lying.
- Rows group by `networkKey`, because that is the unit the daemon tags: the
  thing offered for naming must be the thing the name applies to. A keyless row
  stays visible and simply has no action.

Pinned by `tests/test_peers.js`.

## 6. Verification

The spacing tiers (`padTight/padGroup/padSection/padEdge`)
stay—`PanelSectionHeader` and `PanelSeparator` replace the hand-rolled group
headers, not the rhythm.

⚠️ `PanelToolTip` renders one unwrapped line (upstream omacom/omarchy#12213), so
cap any tooltip added to the trailing cluster.

⚠️ Test with `/usr/lib/qt6/bin/qml`—`/usr/bin/qml` is Qt5 and exits **0** on
failure. Deploy with `bash ~/vallum-preview.sh`; the installed plugin is a copy,
not this repo.
