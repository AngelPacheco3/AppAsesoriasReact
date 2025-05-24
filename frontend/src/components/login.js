// Login.js
import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios'; // ✅ Cambia la importación si ya eliminaste axiosConfig.js

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  // Función para manejar el envío del formulario
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('/api/login', { email, password }, { withCredentials: true });
      
      console.log(response.data);  // 🔍 Verifica la respuesta del backend

      if (response.data.redirect) {
            const rutaDestino = response.data.redirect.replace("/api/", "/");  // 🔄 Corrige la ruta para React
      navigate(rutaDestino);  // ✅ Redirige correctamente dentro de React Router
      } else {
        setError('Error en la redirección después del login.');
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Error en el inicio de sesión');
    }
  };

  // Simula un mensaje de alerta
  const mostrarMensaje = () => {
    alert('Una disculpa, pero por el momento estamos teniendo problemas técnicos. Por favor, intente más tarde.');
  };

  return (
    <div className="container d-flex justify-content-center align-items-center" style={{ minHeight: '100vh' }}>
      <div className="login-box border p-4 text-white rounded shadow-lg">
        <h2 className="text-center mb-4">Inicio de sesión</h2>
        {error && <p className="text-center text-danger">{error}</p>}
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="email" className="text-white">Correo Electrónico</label>
            <input
              type="email"
              className="form-control"
              name="email"
              placeholder="Ejemplo: usuario@correo.com"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="form-group">
            <label htmlFor="password" className="text-white">Contraseña</label>
            <input
              type="password"
              className="form-control"
              name="password"
              placeholder="Contraseña"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <button type="submit" className="btn btn-light btn-block">
            Iniciar Sesión
          </button>
        </form>
        <hr className="bg-light" />
        <div className="text-center">Otras opciones de inicio de sesión</div>
        <div className="d-flex justify-content-around mt-2 p-2 bg-white" style={{ borderRadius: '10px' }}>
          <button className="btn btn-outline-dark" onClick={mostrarMensaje}>X</button>
          <button className="btn btn-outline-danger" onClick={mostrarMensaje}>Google</button>
          <button className="btn btn-outline-primary" onClick={mostrarMensaje}>Facebook</button>
        </div>
        <hr className="bg-light" />
        <div className="text-center">
          <Link to="/crear_usuario" className="text-white">¿No tienes una cuenta? Regístrate</Link>
        </div>
      </div>
    </div>
  );
};

export default Login;
