// Minimal glob matcher (no dependencies). Supports `**`, `*`, `?` and `{a,b}`.
// Patterns are repo-relative. A pattern without a slash matches a basename at
// any depth, so `*.md` behaves like `**/*.md`.

const cache = new Map();

export function globToRegExp(pattern) {
  let src = "";
  let i = 0;
  const p = pattern.includes("/") ? pattern.replace(/^\//, "") : `**/${pattern}`;
  while (i < p.length) {
    const c = p[i];
    if (c === "*") {
      if (p[i + 1] === "*") {
        // `**/` matches zero or more directories; a trailing `**` matches anything.
        if (p[i + 2] === "/") {
          src += "(?:[^/]+/)*";
          i += 3;
        } else {
          src += ".*";
          i += 2;
        }
      } else {
        src += "[^/]*";
        i += 1;
      }
    } else if (c === "?") {
      src += "[^/]";
      i += 1;
    } else if (c === "{") {
      const end = p.indexOf("}", i);
      if (end === -1) {
        src += "\\{";
        i += 1;
      } else {
        const alts = p.slice(i + 1, end).split(",").map(escape);
        src += `(?:${alts.join("|")})`;
        i = end + 1;
      }
    } else {
      src += escape(c);
      i += 1;
    }
  }
  return new RegExp(`^${src}$`);
}

function escape(s) {
  return s.replace(/[.+^$()|[\]\\]/g, "\\$&");
}

export function matchesAny(path, patterns = []) {
  return patterns.some((pattern) => {
    let re = cache.get(pattern);
    if (!re) {
      re = globToRegExp(pattern);
      cache.set(pattern, re);
    }
    return re.test(path);
  });
}
