import React, { useEffect, useRef } from 'react';

const Terminal = ({ output, isLoading, className = '', parsedData = null }) => {
  const terminalRef = useRef(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [output]);

  const formatOutput = (text) => {
    if (!text) return '';
    
    // Add syntax highlighting for common patterns
    return text
      .replace(/(✓|SUCCESS|PASS|ENABLED)/gi, '<span class="text-green-400">$1</span>')
      .replace(/(✗|ERROR|FAIL|FAILED|DISABLED)/gi, '<span class="text-red-400">$1</span>')
      .replace(/(WARNING|WARN)/gi, '<span class="text-yellow-400">$1</span>')
      .replace(/(Device:|IP:|Status:|Control:)/gi, '<span class="text-blue-400">$1</span>')
      .replace(/(\d+\.\d+\.\d+\.\d+)/g, '<span class="text-cyan-400">$1</span>') // IP addresses
      .replace(/(\d+%)/g, '<span class="text-purple-400">$1</span>'); // Percentages
  };

  return (
    <div className={`terminal-output ${className}`} ref={terminalRef}>
      {output && (
        <div 
          className="whitespace-pre-wrap"
          dangerouslySetInnerHTML={{ __html: formatOutput(output) }}
        />
      )}
      
      {parsedData && (
        <div className="mt-4 p-3 bg-gray-800 dark:bg-gray-900 rounded border border-gray-600">
          <div className="text-blue-400 font-semibold mb-2">Parsed Results:</div>
          <pre className="text-sm text-gray-300">
            {JSON.stringify(parsedData, null, 2)}
          </pre>
        </div>
      )}
      
      {isLoading && (
        <div className="flex items-center space-x-2 mt-2">
          <div className="loading-spinner" />
          <span className="text-green-400 dark:text-dark-orange">Processing...</span>
        </div>
      )}
      
      {!output && !isLoading && (
        <div className="text-gray-500 dark:text-gray-400 italic">
          Output will appear here...
        </div>
      )}
    </div>
  );
};

export default Terminal;