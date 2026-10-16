package sudoers

import (
	"fmt"
	"sort"
)

// Post-parse checks run by visudo's check_syntax(): Defaults values
// (update_defaults and check_defaults) and aliases (check_aliases).

func (p *parser) postParseChecks() {
	// update_defaults() runs the "runchroot" callback for Defaults that
	// apply here; only unbound Defaults are known to apply.
	for _, d := range p.defaults {
		if d.kind == tDEFAULTS && d.variable == "runchroot" && checkDefault(d) == nil {
			p.add(SeverityWarning, d.file, d.line, d.column,
				`"runchroot" is deprecated and will be removed in a future sudo release`)
		}
	}

	for _, d := range p.defaults {
		for _, msg := range checkDefault(d) {
			p.add(SeverityError, d.file, d.line, d.column, msg)
		}
	}

	p.checkAliases()
}

// checkAliases reports undefined aliases and alias cycles (errors in
// strict mode, warnings otherwise), then unused aliases (warnings).
func (p *parser) checkAliases() {
	sev := SeverityWarning
	if p.opts.Strict {
		sev = SeverityError
	}
	warned := map[string]bool{}

	var check func(name string, typ aliasType, file string, line, column int)
	check = func(name string, typ aliasType, file string, line, column int) {
		a := p.aliases[aliasKey{name, typ}]
		if a != nil && !a.used {
			a.used = true
			for _, m := range a.members {
				if m.typ == mALIAS {
					check(m.name, typ, a.file, a.line, a.column)
				}
			}
			a.used = false
			return
		}
		if warned[name] {
			return
		}
		if a != nil {
			p.add(sev, file, line, column, fmt.Sprintf(`cycle in %s "%s"`, typ, name))
		} else {
			p.add(sev, file, line, column, fmt.Sprintf(`%s "%s" referenced but not defined`, typ, name))
		}
		warned[name] = true
	}
	checkList := func(members []member, typ aliasType, us *userspec) {
		for _, m := range members {
			if m.typ == mALIAS {
				check(m.name, typ, us.file, us.line, us.column)
			}
		}
	}

	for _, us := range p.userspecs {
		checkList(us.users, aUser, us)
		for _, priv := range us.privs {
			checkList(priv.hosts, aHost, us)
			for _, cs := range priv.cmnds {
				checkList(cs.runasUsers, aRunas, us)
				checkList(cs.runasGroups, aRunas, us)
				checkList([]member{cs.cmnd}, aCmnd, us)
			}
		}
	}

	// Reverse check: remove every alias that is referenced, directly or
	// through other aliases, and report what remains.
	unused := make(map[aliasKey]*alias, len(p.aliases))
	for k, a := range p.aliases {
		unused[k] = a
	}
	var markUsed func(members []member, typ aliasType)
	markUsed = func(members []member, typ aliasType) {
		for _, m := range members {
			if m.typ != mALIAS {
				continue
			}
			k := aliasKey{m.name, typ}
			if a, ok := unused[k]; ok {
				delete(unused, k)
				markUsed(a.members, typ)
			}
		}
	}
	for _, us := range p.userspecs {
		markUsed(us.users, aUser)
		for _, priv := range us.privs {
			markUsed(priv.hosts, aHost)
			for _, cs := range priv.cmnds {
				markUsed(cs.runasUsers, aRunas)
				markUsed(cs.runasGroups, aRunas)
				markUsed([]member{cs.cmnd}, aCmnd)
			}
		}
	}
	for _, d := range p.defaults {
		switch d.kind {
		case tDEFAULTS_HOST:
			markUsed(d.binding, aHost)
		case tDEFAULTS_USER:
			markUsed(d.binding, aUser)
		case tDEFAULTS_RUNAS:
			markUsed(d.binding, aRunas)
		case tDEFAULTS_CMND:
			markUsed(d.binding, aCmnd)
		}
	}

	remaining := make([]*alias, 0, len(unused))
	for _, a := range unused {
		remaining = append(remaining, a)
	}
	sort.Slice(remaining, func(i, j int) bool {
		if remaining[i].name != remaining[j].name {
			return remaining[i].name < remaining[j].name
		}
		return remaining[i].typ < remaining[j].typ
	})
	for _, a := range remaining {
		p.add(SeverityWarning, a.file, a.line, a.column,
			fmt.Sprintf(`unused %s "%s"`, a.typ, a.name))
	}
}
