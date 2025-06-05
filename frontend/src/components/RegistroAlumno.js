import React, { useState, useEffect } from 'react';
import axios from '../axiosConfig';  // o '../axiosConfig' según la ubicación
import { useNavigate } from 'react-router-dom';

const RegistroAlumno = () => {
  const [formData, setFormData] = useState({
    nombre: '',
    email: '',
    password: '',
    confirm_password: ''
  });
  const [error, setError] = useState('');
  const [passwordErrors, setPasswordErrors] = useState([]);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  // 🆕 Función para validar fortaleza de contraseña
  const validatePasswordStrength = (password) => {
    const errors = [];
    if (password.length < 8) errors.push('Mínimo 8 caracteres');
    if (!/[A-Z]/.test(password)) errors.push('Al menos una mayúscula');
    if (!/[a-z]/.test(password)) errors.push('Al menos una minúscula');
    if (!/\d/.test(password)) errors.push('Al menos un número');
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) errors.push('Al menos un carácter especial');
    return errors;
  };

  // 🆕 Validar contraseña en tiempo real
  useEffect(() => {
    if (formData.password) {
      const errors = validatePasswordStrength(formData.password);
      setPasswordErrors(errors);
    } else {
      setPasswordErrors([]);
    }
  }, [formData.password]);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
    
    // Limpiar errores cuando el usuario modifica los campos
    if (error) setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    // Validaciones del frontend
    if (formData.password !== formData.confirm_password) {
      setError('Las contraseñas no coinciden.');
      setLoading(false);
      return;
    }

    if (passwordErrors.length > 0) {
      setError('La contraseña no cumple todos los requisitos de seguridad.');
      setLoading(false);
      return;
    }

    try {
      const response = await axios.post('/api/registro_alumno', formData);
      
      if (response.data.message) {
        alert('✅ Registro exitoso. Ya puedes iniciar sesión.');
        navigate('/login');
      }
    } catch (err) {
      console.error('Error en registro:', err);
      
      // 🆕 MEJORADO: Manejo específico de errores del backend
      if (err.response?.status === 400) {
        const errorData = err.response.data;
        if (errorData.details && Array.isArray(errorData.details)) {
          setError(`${errorData.error}\nRequisitos faltantes: ${errorData.details.join(', ')}`);
        } else {
          setError(errorData.error || 'Error al registrar alumno.');
        }
      } else {
        setError('Error en el servidor. Intenta de nuevo.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container-fluid">
      <button 
        className="btn btn-custom btn-back"
        onClick={() => navigate('/crear_usuario')}
      >
        ←
      </button>

      <div className="login-box mt-5">
        <h2 className="text-center mb-4">Registro de Alumno</h2>
        
        {/* 🆕 MEJORADO: Mejor visualización de errores */}
        {error && (
          <div className="alert alert-danger" role="alert">
            <small style={{ whiteSpace: 'pre-line' }}>{error}</small>
          </div>
        )}
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="nombre">Nombre</label>
            <input 
              type="text"
              className="form-control"
              id="nombre"
              name="nombre"
              value={formData.nombre}
              onChange={handleChange}
              disabled={loading}
              required
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="email">Correo Electrónico</label>
            <input 
              type="email"
              className="form-control"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              disabled={loading}
              required
            />
          </div>
          
          {/* 🆕 NUEVO: Campo de contraseña con validación visual */}
          <div className="form-group">
            <label htmlFor="password">
              Contraseña 
              <small className="text-muted">(mínimo 8 caracteres, con mayúscula, minúscula, número y símbolo)</small>
            </label>
            <div className="input-group">
              <input 
                type={showPassword ? "text" : "password"}
                className={`form-control ${passwordErrors.length > 0 && formData.password ? 'is-invalid' : formData.password && passwordErrors.length === 0 ? 'is-valid' : ''}`}
                id="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                disabled={loading}
                required
              />
              <div className="input-group-append">
                <button
                  className="btn btn-outline-secondary"
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={loading}
                >
                  {showPassword ? '🙈' : '👁️'}
                </button>
              </div>
            </div>
            
            {/* 🆕 NUEVO: Indicadores de requisitos de contraseña */}
            {formData.password && (
              <div className="mt-2">
                <small className="text-muted">Requisitos de contraseña:</small>
                <ul className="list-unstyled mt-1">
                  <li className={formData.password.length >= 8 ? 'text-success' : 'text-danger'}>
                    {formData.password.length >= 8 ? '✅' : '❌'} Mínimo 8 caracteres
                  </li>
                  <li className={/[A-Z]/.test(formData.password) ? 'text-success' : 'text-danger'}>
                    {/[A-Z]/.test(formData.password) ? '✅' : '❌'} Al menos una mayúscula
                  </li>
                  <li className={/[a-z]/.test(formData.password) ? 'text-success' : 'text-danger'}>
                    {/[a-z]/.test(formData.password) ? '✅' : '❌'} Al menos una minúscula
                  </li>
                  <li className={/\d/.test(formData.password) ? 'text-success' : 'text-danger'}>
                    {/\d/.test(formData.password) ? '✅' : '❌'} Al menos un número
                  </li>
                  <li className={/[!@#$%^&*(),.?":{}|<>]/.test(formData.password) ? 'text-success' : 'text-danger'}>
                    {/[!@#$%^&*(),.?":{}|<>]/.test(formData.password) ? '✅' : '❌'} Al menos un carácter especial
                  </li>
                </ul>
              </div>
            )}
          </div>
          
          <div className="form-group">
            <label htmlFor="confirm_password">Confirmar Contraseña</label>
            <input 
              type={showPassword ? "text" : "password"}
              className={`form-control ${formData.confirm_password && formData.password !== formData.confirm_password ? 'is-invalid' : formData.confirm_password && formData.password === formData.confirm_password ? 'is-valid' : ''}`}
              id="confirm_password"
              name="confirm_password"
              value={formData.confirm_password}
              onChange={handleChange}
              disabled={loading}
              required
            />
            {formData.confirm_password && formData.password !== formData.confirm_password && (
              <div className="invalid-feedback">
                Las contraseñas no coinciden
              </div>
            )}
          </div>
          
          {/* 🆕 MEJORADO: Botón con validación */}
          <button 
            type="submit" 
            className="btn btn-primary btn-block"
            disabled={loading || passwordErrors.length > 0 || formData.password !== formData.confirm_password}
          >
            {loading ? '⏳ Registrando...' : '📝 Registrar'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default RegistroAlumno;