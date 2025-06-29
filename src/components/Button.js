import React from 'react';

const Button = ({ 
  children, 
  onClick, 
  variant = 'primary', 
  size = 'md', 
  disabled = false, 
  loading = false,
  className = '',
  ...props 
}) => {
  const baseClasses = 'inline-flex items-center justify-center font-medium rounded-md transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2';
  
  const variants = {
    primary: 'bg-artemis-primary dark:bg-dark-orange hover:bg-red-700 dark:hover:bg-dark-orange-light text-white focus:ring-red-500 dark:focus:ring-dark-orange',
    secondary: 'bg-gray-600 dark:bg-dark-accent hover:bg-gray-700 dark:hover:bg-dark-surface text-white focus:ring-gray-500 dark:focus:ring-dark-orange',
    success: 'bg-green-600 hover:bg-green-700 text-white focus:ring-green-500',
    warning: 'bg-yellow-600 hover:bg-yellow-700 text-white focus:ring-yellow-500',
    danger: 'bg-red-600 hover:bg-red-700 text-white focus:ring-red-500',
    outline: 'border border-gray-300 dark:border-dark-accent bg-white dark:bg-dark-secondary hover:bg-gray-50 dark:hover:bg-dark-accent text-gray-700 dark:text-gray-300 focus:ring-gray-500 dark:focus:ring-dark-orange'
  };

  const sizes = {
    sm: 'px-3 py-2 text-sm',
    md: 'px-4 py-2 text-sm',
    lg: 'px-6 py-3 text-base'
  };

  const disabledClasses = disabled || loading ? 'opacity-50 cursor-not-allowed' : 'artemis-button';

  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      className={`${baseClasses} ${variants[variant]} ${sizes[size]} ${disabledClasses} ${className}`}
      {...props}
    >
      {loading && (
        <div className="loading-spinner mr-2" />
      )}
      {children}
    </button>
  );
};

export default Button;