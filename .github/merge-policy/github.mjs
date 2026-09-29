// Thin GitHub REST/GraphQL client on fetch (Node 20+). No dependencies.

const API = process.env.GITHUB_API_URL || "https://api.github.com";

export class GitHub {
  constructor(token, repo) {
    if (!token) throw new Error("missing GitHub token");
    this.token = token;
    this.repo = repo;
  }

  async request(method, path, body, { allow404 = false } = {}) {
    const url = path.startsWith("http") ? path : `${API}${path.replace("{repo}", this.repo)}`;
    const res = await fetch(url, {
      method,
      headers: {
        authorization: `Bearer ${this.token}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        ...(body ? { "content-type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (allow404 && res.status === 404) return { data: null, res };
    const text = await res.text();
    const data = text ? JSON.parse(text) : null;
    if (!res.ok) {
      const err = new Error(`${method} ${path} -> ${res.status}: ${data?.message || text}`);
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return { data, res };
  }

  get(path, opts) {
    return this.request("GET", path, undefined, opts).then((r) => r.data);
  }
  post(path, body) {
    return this.request("POST", path, body).then((r) => r.data);
  }
  patch(path, body) {
    return this.request("PATCH", path, body).then((r) => r.data);
  }
  put(path, body) {
    return this.request("PUT", path, body).then((r) => r.data);
  }
  delete(path) {
    return this.request("DELETE", path, undefined, { allow404: true }).then((r) => r.data);
  }

  /** Binary download (artifact zips). The API answers with a redirect to a
   * pre-signed URL, which is fetched without our credentials. */
  async download(path) {
    const url = path.startsWith("http") ? path : `${API}${path.replace("{repo}", this.repo)}`;
    const res = await fetch(url, {
      headers: { authorization: `Bearer ${this.token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28" },
      redirect: "manual",
    });
    const location = res.status >= 300 && res.status < 400 ? res.headers.get("location") : null;
    const final = location ? await fetch(location) : res;
    if (!final.ok) throw new Error(`GET ${path} -> ${final.status}`);
    return Buffer.from(await final.arrayBuffer());
  }

  /** A file's raw content from the contents API, as text. Refuses (throws)
   * anything larger than `maxBytes` without reading it all. */
  async raw(path, maxBytes = Infinity) {
    const url = path.startsWith("http") ? path : `${API}${path.replace("{repo}", this.repo)}`;
    const res = await fetch(url, {
      headers: { authorization: `Bearer ${this.token}`, accept: "application/vnd.github.raw", "x-github-api-version": "2022-11-28" },
    });
    if (!res.ok) {
      await res.body?.cancel();
      throw new Error(`GET ${path} -> ${res.status}`);
    }
    const length = Number(res.headers.get("content-length"));
    if (Number.isFinite(length) && length > maxBytes) {
      await res.body?.cancel();
      throw new Error(`GET ${path}: ${length} bytes > ${maxBytes}`);
    }
    const text = await res.text();
    if (Buffer.byteLength(text) > maxBytes) throw new Error(`GET ${path}: more than ${maxBytes} bytes`);
    return text;
  }

  /** Follows Link: rel="next" until exhausted. `key` picks the array out of an object page. */
  async paginate(path, key) {
    const out = [];
    let next = `${API}${path.replace("{repo}", this.repo)}${path.includes("?") ? "&" : "?"}per_page=100`;
    while (next) {
      const { data, res } = await this.request("GET", next);
      const page = key ? data[key] : data;
      if (!Array.isArray(page)) throw new Error(`expected an array page from ${path}`);
      out.push(...page);
      const link = res.headers.get("link") || "";
      next = link.match(/<([^>]+)>;\s*rel="next"/)?.[1] || null;
    }
    return out;
  }

  async graphql(query, variables) {
    const { data } = await this.request("POST", "/graphql", { query, variables });
    if (data.errors?.length) {
      const err = new Error(data.errors.map((e) => e.message).join("; "));
      err.graphql = data.errors;
      throw err;
    }
    return data.data;
  }
}
