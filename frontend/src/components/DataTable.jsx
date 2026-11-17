import React, { useState } from 'react';
import { Search } from 'lucide-react';

export default function DataTable({ columns = [], data = [], searchPlaceholder = "Search records...", rowKey = "id" }) {
  const [searchTerm, setSearchTerm] = useState('');

  const safeData = Array.isArray(data) ? data : [];
  const safeColumns = Array.isArray(columns) ? columns : [];

  const filteredData = safeData.filter((row) => {
    if (!searchTerm) return true;
    if (!row) return false;
    return Object.values(row).some((val) =>
      String(val).toLowerCase().includes(searchTerm.toLowerCase())
    );
  });

  return (
    <div className="cyber-card rounded-xl border border-slate-800 overflow-hidden">
      <div className="p-4 border-b border-slate-800 flex items-center justify-between gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder={searchPlaceholder}
            className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="text-xs text-slate-400 font-mono">
          Showing <span className="text-cyan-400">{filteredData.length}</span> of {safeData.length} records
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="bg-[#0b1329] text-xs uppercase font-mono tracking-wider text-slate-400 border-b border-slate-800">
            <tr>
              {safeColumns.map((col, idx) => (
                <th key={idx} className="px-5 py-3 font-semibold">
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-sans">
            {filteredData.length > 0 ? (
              filteredData.map((row, idx) => (
                <tr key={row[rowKey] || idx} className="hover:bg-slate-800/40 transition-colors">
                  {safeColumns.map((col, cIdx) => (
                    <td key={cIdx} className="px-5 py-3 text-slate-300">
                      {col.render ? col.render(row) : row[col.accessor]}
                    </td>
                  ))}
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={safeColumns.length || 1} className="px-5 py-8 text-center text-slate-500">
                  No records found matching criteria
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

