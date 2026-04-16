import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { Shield, Lock, User, AlertCircle, Loader2, ArrowRight } from 'lucide-react';
import useStore from '../store/useStore';
import api from '../services/api';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  const login = useStore((state) => state.login);
  const navigate = useNavigate();
  const location = useLocation();
  
  const from = location.state?.from?.pathname || '/';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      // API expects form data for standard OAuth2 login
      const formData = new FormData();
      formData.append('username', username);
      formData.append('password', password);

      const response = await api.post('/auth/token', formData);
      const { access_token } = response.data;

      // Now fetch user details
      const userRes = await api.get('/auth/users/me', {
        headers: { Authorization: `Bearer ${access_token}` }
      });

      login(userRes.data, access_token);
      navigate(from, { replace: true });
    } catch (err) {
      console.error('Login error:', err);
      setError(err.response?.data?.detail || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0A0A0B] flex items-center justify-center p-4 relative overflow-hidden font-sans">
      {/* Dynamic Background Elements */}
      <div className="absolute top-[-10%] right-[-10%] w-[40%] h-[40%] bg-metalgold-main/5 blur-[120px] rounded-full animate-pulse" />
      <div className="absolute bottom-[-10%] left-[-10%] w-[40%] h-[40%] bg-metalgold-main/5 blur-[120px] rounded-full animate-pulse" style={{ animationDelay: '2s' }} />
      <div
        className="absolute inset-0 opacity-20 pointer-events-none"
        style={{
          backgroundImage: 'radial-gradient(circle at top left, rgba(255,255,255,0.08), transparent 20%), radial-gradient(circle at bottom right, rgba(212,175,55,0.08), transparent 30%)'
        }}
      />

      <div className="w-full max-w-md relative z-10">
        {/* Logo Section */}
        <div className="flex flex-col items-center mb-10 animate-in fade-in slide-in-from-top duration-700">
          <div className="w-16 h-16 rounded-2xl bg-metalgold-main/10 border border-metalgold-main/20 flex items-center justify-center mb-4 shadow-xl shadow-metalgold-main/5 group">
            <Shield className="text-metalgold-main group-hover:scale-110 transition-transform duration-500" size={32} />
          </div>
          <h1 className="text-3xl font-black text-metaltxt-primary tracking-[0.2em] uppercase">CNS AegisNet</h1>
          <p className="text-metalsilver-muted text-[10px] font-bold uppercase tracking-[0.4em] mt-2">Tactical Intelligence Portal</p>
        </div>

        {/* Login Form Card */}
        <div className="soc-card overflow-hidden animate-in fade-in zoom-in-95 duration-700 delay-200">
          <div className="p-8 space-y-6">
            <div className="space-y-2">
              <h2 className="text-xl font-black text-metaltxt-primary tracking-wide uppercase">Operator Login</h2>
              <p className="text-xs text-metalsilver-muted font-bold">Secure biometric & credential verification required.</p>
            </div>

            {error && (
              <div className="flex items-center space-x-3 p-4 bg-m-critical/10 border border-m-critical/20 rounded-xl text-m-critical text-xs font-bold animate-in shake duration-300">
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-5">
              <div className="space-y-1.5">
                <label className="text-[10px] font-black text-metalsilver-muted uppercase tracking-widest ml-1">Username / ID</label>
                <div className="relative group">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-metalsilver-muted group-focus-within:text-metalgold-main transition-colors">
                    <User size={18} />
                  </div>
                  <input 
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    className="w-full bg-metalbg-main/50 border border-metal-border rounded-xl py-3.5 pl-11 pr-4 text-metaltxt-primary text-sm font-bold focus:outline-none focus:border-metalgold-main focus:bg-metalbg-main transition-all placeholder:text-metalsilver-muted/30"
                    placeholder="ENTER ID..."
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="flex justify-between items-center ml-1">
                  <label className="text-[10px] font-black text-metalsilver-muted uppercase tracking-widest">Access Key</label>
                  <a href="#" className="text-[9px] font-black text-metalgold-main uppercase hover:text-metalgold-bright transition-colors tracking-tighter">Emergency Override?</a>
                </div>
                <div className="relative group">
                  <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-metalsilver-muted group-focus-within:text-metalgold-main transition-colors">
                    <Lock size={18} />
                  </div>
                  <input 
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="w-full bg-metalbg-main/50 border border-metal-border rounded-xl py-3.5 pl-11 pr-4 text-metaltxt-primary text-sm font-bold focus:outline-none focus:border-metalgold-main focus:bg-metalbg-main transition-all placeholder:text-metalsilver-muted/30"
                    placeholder="••••••••"
                  />
                </div>
              </div>

              <button 
                type="submit"
                disabled={isLoading}
                className="w-full relative group overflow-hidden"
              >
                <div className="absolute inset-0 bg-gradient-to-r from-metalgold-main to-metalgold-muted opacity-100 group-hover:scale-105 transition-transform duration-500" />
                <div className="relative h-[52px] flex items-center justify-center space-x-3 text-metalbg-main font-black text-xs uppercase tracking-[0.2em] transition-all">
                  {isLoading ? (
                    <Loader2 className="animate-spin" size={18} />
                  ) : (
                    <>
                      <span>Initialize Link</span>
                      <ArrowRight size={16} className="group-hover:translate-x-1 transition-transform" />
                    </>
                  )}
                </div>
              </button>
            </form>
          </div>

          <div className="px-8 py-5 bg-metalbg-secondary/50 border-t border-metal-border flex items-center justify-center">
            <p className="text-[10px] text-metalsilver-muted font-bold uppercase tracking-widest">
              New Operator? <Link to="/register" className="text-metalgold-main hover:text-metalgold-bright transition-colors ml-1">Request Authorization</Link>
            </p>
          </div>
        </div>

        {/* Terminal Footer */}
        <div className="mt-8 text-center space-y-2 opacity-40">
           <div className="text-[9px] font-mono font-black text-metalsilver-muted uppercase tracking-[0.3em]">Encrypted Session: AES-256-GCM</div>
           <div className="text-[8px] font-mono text-metalsilver-muted/70">© 2026 CNS CYBER OPERATIONS COMMAND. ALL RIGHTS RESERVED.</div>
        </div>
      </div>
    </div>
  );
};

export default Login;
