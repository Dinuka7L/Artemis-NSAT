import React, { useEffect, useRef } from 'react';

const Terminal = ({ output, isLoading, className = '' }) => {
  const terminalRef = useRef(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [output]);

  return (
    <div className={`terminal-output ${className}`} ref={terminalRef}>
      {output && (
        <pre className="whitespace-pre-wrap">{output}</pre>
      )}
      {isLoading && (
        <div className="flex items-center space-x-2 mt-2">
          <div className="loading-spinner" />
          <span className="text-green-400">Processing...</span>
        </div>
      )}
      {!output && !isLoading && (
        <div className="text-gray-500 italic">
          Output will appear here...
        </div>
      )}
    </div>
  );
};

export default Terminal;