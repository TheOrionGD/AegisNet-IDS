import React from 'react';

const Badge = ({ children, variant = 'default', className = '' }) => {
  const baseStyle = "inline-flex items-center px-2.5 py-0.5 rounded-full text-[9px] font-black uppercase tracking-widest border transition-all";
  
  const variants = {
    default: "bg-metalbg-secondary text-metalsilver-muted border-metalsilver-muted/30",
    success: "bg-metalgold-main/5 text-metalsilver-main border-metalgold-main/20",
    warning: "bg-metalgold-main/10 text-metalgold-main border-metalgold-main/30 shadow-[0_0_8px_rgba(212,175,55,0.2)]",
    danger: "bg-m-critical/10 text-m-critical border-m-critical/30",
    critical: "bg-m-critical text-metaltxt-primary border-m-critical shadow-[0_0_10px_rgba(169,68,66,0.5)] animate-gold-pulse",
    gold: "bg-metalgold-main text-metalbg-main border-metalgold-main font-black",
    
    // Status/Severity mapping
    low: "bg-m-low/10 text-m-low border-m-low/30",
    medium: "bg-metalbg-elevated text-metalsilver-muted border-metal-border",
    high: "bg-m-high/10 text-m-high border-m-high/30 shadow-[0_0_5px_rgba(212,175,55,0.1)]",
    open: "bg-metalgold-main/5 text-metalsilver-main border-metalgold-main/20",
    investigating: "bg-metalgold-main/10 text-metalgold-main border-metalgold-main/30",
    resolved: "bg-metalbg-elevated text-metalsilver-muted border-metal-border opacity-50",
  };

  const selectedVariant = variants[variant?.toLowerCase()] || variants.default;

  return (
    <span className={`${baseStyle} ${selectedVariant} ${className}`}>
      {children}
    </span>
  );
};

export default Badge;
