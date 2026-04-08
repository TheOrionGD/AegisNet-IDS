const Card = ({ children, className = '', title, headerAction }) => {
  return (
    <div className={`bg-bgSecondary border border-bgElevated rounded-xl shadow-lg overflow-hidden ${className}`}>
      {(title || headerAction) && (
        <div className="px-5 py-4 border-b border-bgElevated flex justify-between items-center bg-bgSecondary/80 backdrop-blur-sm">
          {title && <h3 className="text-silverMain font-semibold tracking-wide">{title}</h3>}
          {headerAction && <div>{headerAction}</div>}
        </div>
      )}
      <div className="p-5">
        {children}
      </div>
    </div>
  );
};

export default Card;
