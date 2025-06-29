import React from 'react';

const Card = ({ children, className = '', title, subtitle }) => {
  return (
    <div className={`bg-white dark:bg-dark-secondary rounded-lg shadow-md border border-gray-200 dark:border-dark-accent ${className}`}>
      {(title || subtitle) && (
        <div className="px-6 py-4 border-b border-gray-200 dark:border-dark-accent">
          {title && (
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              {title}
            </h3>
          )}
          {subtitle && (
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
              {subtitle}
            </p>
          )}
        </div>
      )}
      <div className="p-6">
        {children}
      </div>
    </div>
  );
};

export default Card;