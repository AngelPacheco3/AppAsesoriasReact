import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios, { saveJWTToken } from '../axiosConfig';  // Importar también saveJWTToken

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const response = await axios.post('/api/login', { email, password });
      
      console.log('Login exitoso:', response.data);

      // NUEVO: Guardar el JWT token
      if (response.data.token) {
        saveJWTToken(response.data.token);
      }

      if (response.data.redirect) {
        const rutaDestino = response.data.redirect.replace("/api/", "/");
        navigate(rutaDestino);
      } else {
        setError('Error en la redirección después del login.');
      }
    } catch (err) {
      console.error('Error en login:', err);
      
      if (err.response?.status === 400) {
        const errorData = err.response.data;
        if (errorData.details && Array.isArray(errorData.details)) {
          setError(`${errorData.error}: ${errorData.details.join(', ')}`);
        } else {
          setError(errorData.error || 'Credenciales incorrectas');
        }
      } else {
        setError('Error en el servidor. Intenta de nuevo.');
      }
    } finally {
      setLoading(false);
    }
  };

  const mostrarMensaje = () => {
    alert('Una disculpa, pero por el momento estamos teniendo problemas técnicos. Por favor, intente más tarde.');
  };

  return (
    <div className="container d-flex justify-content-center align-items-center" style={{ minHeight: '100vh' }}>
      <div className="login-box border p-4 text-white rounded shadow-lg">
        <h2 className="text-center mb-4">Inicio de sesión</h2>
        
        {error && (
          <div className="alert alert-danger" role="alert">
            <small>{error}</small>
          </div>
        )}
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label-oscura htmlFor="email" className="text-white">Correo Electrónico</label-oscura>
            <input
              type="email"
              className="form-control"
              name="email"
              placeholder="Ejemplo: usuario@correo.com"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={loading}
            />
          </div>
          <div className="form-group">
            <label-oscura htmlFor="password" className="text-white">Contraseña</label-oscura>
            <input
              type="password"
              className="form-control"
              name="password"
              placeholder="Contraseña"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading}
            />
          </div>
          
          <button 
            type="submit" 
            className="btn btn-custom-blue btn-block"
            disabled={loading}
          >
            {loading ? 'Iniciando sesión...' : 'Iniciar Sesión'}
          </button>
        </form>
        
        <hr className="bg-light" />
        <label-oscura className="text-center">Otras opciones de inicio de sesión</label-oscura>
        <div className="d-flex justify-content-around mt-2 p-2 bg-white" style={{ borderRadius: '10px' }}>
          <button className="btn btn-outline-dark" onClick={mostrarMensaje}>X</button>
          <button className="btn btn-outline-danger" onClick={mostrarMensaje}>Google</button>
          <button className="btn btn-outline-primary" onClick={mostrarMensaje}>Facebook</button>
        </div>
        <hr className="bg-light" />
        <div className="text-center">
          <Link to="/crear_usuario" className="text-black">¿No tienes una cuenta? Regístrate</Link>
        </div>
      </div>
    </div>
  );
};

export default Login;