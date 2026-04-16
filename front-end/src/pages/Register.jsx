import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ShieldPlus, User, Mail, Lock, AlertCircle, Loader2, CheckCircle2 } from 'lucide-react';
import api from '../services/api';

const Register = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    
    if (formData.password !== formData.confirmPassword) {
      setError('Access keys do not match.');
      return;
    }

    setIsLoading(true);
    try {
      await api.post('/auth/users/', {
        username: formData.username,
        email: formData.email,
        password: formData.password
      });
      
      setIsSuccess(true);
      setTimeout(() => navigate('/login'), 2000);
    } catch (err) {
      console.error('Registration error:', err);
      setError(err.response?.data?.detail || 'Authorization request failed.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0A0A0B] flex items-center justify-center p-4 relative overflow-hidden font-sans">
      {/* Background Elements */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-metalgold-main/5 blur-[120px] rounded-full animate-pulse" />
      <div
        className="absolute inset-0 opacity-20 pointer-events-none"
        style={{
          backgroundImage: 'radial-gradient(circle at top left, rgba(255,255,255,0.08), transparent 20%), radial-gradient(circle at bottom right, rgba(212,175,55,0.08), transparent 30%)'
        }}
      />

      <div className="w-full max-w-md relative z-10">
        <div className="flex flex-col items-center mb-8 animate-in fade-in slide-in-from-top duration-700">
           <div className="w-16 h-16 rounded-2xl bg-metalgold-main/10 border border-metalgold-main/20 flex items-center justify-center mb-4 shadow-xl shadow-metalgold-main/5 group">
             <ShieldPlus className="text-metalgold-main group-hover:scale-110 transition-transform duration-500" size={32} />
           </div>
           <h1 className="text-2xl font-black text-metaltxt-primary tracking-[0.2em] uppercase">Operator Onboarding</h1>
        </div>

        <div className="soc-card overflow-hidden animate-in fade-in zoom-in-95 duration-700">
          <div className="p-8 space-y-6">
            {isSuccess ? (
              <div className="flex flex-col items-center justify-center py-10 space-y-4 text-center">
                 <div className="w-20 h-20 rounded-full bg-metalgold-main/10 border border-metalgold-main/20 flex items-center justify-center text-metalgold-main mb-2">
                   <CheckCircle2 size={40} className="animate-bounce" />
                 </div>
                 <h2 className="text-xl font-black text-metaltxt-primary uppercase tracking-wide">Request Recorded</h2>
                 <p className="text-xs text-metalsilver-muted font-bold leading-relaxed px-4">Your operator credentials have been established. Redirecting to terminal...</p>
              </div>
            ) : (
              <>
                <div className="space-y-2">
                  <h2 className="text-lg font-black text-metaltxt-primary tracking-wide uppercase">Credentials Setup</h2>
                  <p className="text-[10px] text-metalsilver-muted font-bold uppercase tracking-wider">Initialize your CNS Tactical Identity.</p>
                </div>

                {error && (
                  <div className="flex items-center space-x-3 p-4 bg-m-critical/10 border border-m-critical/20 rounded-xl text-m-critical text-xs font-bold">
                    <AlertCircle size={16} />
                    <span>{error}</span>
                  </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="text-[10px] font-black text-metalsilver-muted uppercase tracking-widest ml-1">Username</label>
                      <div className="relative group">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-metalsilver-muted">
                          <User size={14} />
                        </div>
                        <input 
                          name="username"
                          type="text"
                          value={formData.username}
                          onChange={handleChange}
                          required
                          className="w-full bg-metalbg-main/50 border border-metal-border rounded-xl py-2.5 pl-9 pr-3 text-metaltxt-primary text-[11px] font-bold focus:outline-none focus:border-metalgold-main transition-all"
                          placeholder="OP_77X"
                        />
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-[10px] font-black text-metalsilver-muted uppercase tracking-widest ml-1">Email</label>
                      <div className="relative group">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-metalsilver-muted">
                          <Mail size={14} />
                        </div>
                        <input 
                          name="email"
                          type="email"
                          value={formData.email}
                          onChange={handleChange}
                          required
                          className="w-full bg-metalbg-main/50 border border-metal-border rounded-xl py-2.5 pl-9 pr-3 text-metaltxt-primary text-[11px] font-bold focus:outline-none focus:border-metalgold-main transition-all"
                          placeholder="operator@cns.io"
                        />
                      </div>
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[10px] font-black text-metalsilver-muted uppercase tracking-widest ml-1">Access Key (Password)</label>
                    <div className="relative group">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-metalsilver-muted">
                        <Lock size={14} />
                      </div>
                      <input 
                        name="password"
                        type="password"
                        value={formData.password}
                        onChange={handleChange}
                        required
                        className="w-full bg-metalbg-main/50 border border-metal-border rounded-xl py-2.5 pl-9 pr-3 text-metaltxt-primary text-[11px] font-bold focus:outline-none focus:border-metalgold-main transition-all"
                        placeholder="••••••••"
                      />
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[10px] font-black text-metalsilver-muted uppercase tracking-widest ml-1">Verify Access Key</label>
                    <div className="relative group">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-metalsilver-muted">
                        <Lock size={14} />
                      </div>
                      <input 
                        name="confirmPassword"
                        type="password"
                        value={formData.confirmPassword}
                        onChange={handleChange}
                        required
                        className="w-full bg-metalbg-main/50 border border-metal-border rounded-xl py-2.5 pl-9 pr-3 text-metaltxt-primary text-[11px] font-bold focus:outline-none focus:border-metalgold-main transition-all"
                        placeholder="••••••••"
                      />
                    </div>
                  </div>

                  <button 
                    type="submit"
                    disabled={isLoading}
                    className="w-full relative group mt-4"
                  >
                    <div className="aspect-[8/1] bg-gradient-to-r from-metalgold-main to-metalgold-muted rounded-xl transition-all group-hover:shadow-[0_0_20px_rgba(212,175,55,0.3)]" />
                    <div className="absolute inset-0 flex items-center justify-center text-metalbg-main font-black text-[10px] uppercase tracking-[0.3em]">
                      {isLoading ? <Loader2 className="animate-spin" size={16} /> : 'Submit Credentials'}
                    </div>
                  </button>
                </form>
              </>
            )}
          </div>

          <div className="px-8 py-5 bg-metalbg-secondary/50 border-t border-metal-border flex items-center justify-center">
            <p className="text-[10px] text-metalsilver-muted font-bold uppercase tracking-widest">
              Already Authorized? <Link to="/login" className="text-metalgold-main hover:text-metalgold-bright transition-colors ml-1">Terminal Login</Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;
