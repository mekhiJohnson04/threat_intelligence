import { useState } from "react"

export default function SearchBar({ onSearch, loading }) {
  const [query, setQuery] = useState("")

  const handleSubmit = () => {
    if (query.trim()) onSearch(query)
  }

  const handleKeyDown = (e) => {
    if (e.key === "Enter") handleSubmit()
  }

  return (
    <div className="search-bar">
      <input
        type="text"
        value={query}
        onChange={e => setQuery(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="e.g. lateral movement SMB, T1059, credential dumping..."
        disabled={loading}
      />
      <button onClick={handleSubmit} disabled={loading || !query.trim()}>
        {loading ? "Analyzing..." : "Analyze"}
      </button>
    </div>
  )
}
