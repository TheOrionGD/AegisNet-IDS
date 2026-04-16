const Card = ({ children, className = '', title, subtitle, headerAction }) => {
  return (
    <div className={`soc-card overflow-hidden ${className}`}>
      {(title || subtitle || headerAction) && (
        <div className="px-6 py-4 border-b border-border flex justify-between items-center bg-bg-elevated/20 transition-colors">
          <div className="flex flex-col">
            {title && <h3 className="text-xs font-black text-metaltxt-primary uppercase tracking-[0.2em]">{title}</h3>}
            {subtitle && <p className="text-[10px] text-metalsilver-muted mt-1 uppercase font-bold tracking-widest">{subtitle}</p>}
          </div>
          {headerAction && <div>{headerAction}</div>}
        </div>
      )}
      <div className="p-6">
        {children}
      </div>
    </div>
  );
};

export default Card;
