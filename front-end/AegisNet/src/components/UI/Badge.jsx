const Badge = ({ children, variant = 'default', className = '' }) => {
  const baseStyle = "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium uppercase tracking-wider";
  
  const variants = {
    default: "bg-bgElevated text-silverSoft border border-silverMuted/30",
    success: "bg-green-500/10 text-green-400 border border-green-500/20",
    warning: "bg-yellow-500/10 text-yellow-500 border border-yellow-500/20",
    danger: "bg-red-500/10 text-red-500 border border-red-500/20",
    critical: "bg-red-600 animate-pulse text-white shadow-[0_0_10px_rgba(220,38,38,0.6)]",
    gold: "bg-goldMain/10 text-goldHover border border-goldMain/30",
    
    // Specific status/severity mappings
    low: "bg-blue-500/10 text-blue-400 border border-blue-500/20",
    medium: "bg-yellow-500/10 text-yellow-500 border border-yellow-500/20",
    high: "bg-red-500/10 text-red-400 border border-red-500/20",
    open: "bg-red-500/10 text-red-400 border border-red-500/20",
    investigating: "bg-yellow-500/10 text-yellow-500 border border-yellow-500/20",
    resolved: "bg-green-500/10 text-green-400 border border-green-500/20",
  };

  const selectedVariant = variants[variant.toLowerCase()] || variants.default;

  return (
    <span className={`${baseStyle} ${selectedVariant} ${className}`}>
      {children}
    </span>
  );
};

export default Badge;
