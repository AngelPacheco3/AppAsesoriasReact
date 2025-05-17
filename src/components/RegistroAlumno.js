import React, { useState } from 'react';
import axios from '../axiosConfig'; // Asegúrate de que la ruta sea correcta
import { useNavigate } from 'react-router-dom';

const RegistroAlumno = () => {
  const [formData, setFormData] = useState({
    nombre: '',
    email: '',
    password: '',
    confirm_password: ''
  });
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (formData.password !== formData.confirm_password) {
      setError('Las contraseñas no coinciden.');
      return;
    }

    try {
      await axios.post('/api/registro_alumno', formData);
      alert('Registro exitoso.');
      navigate('/login');
    } catch (err) {
      setError('Error al registrar alumno.');
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
        {error && <p className="text-danger text-center">{error}</p>}
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
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="password">Contraseña</label>
            <input 
              type="password"
              className="form-control"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="confirm_password">Confirmar Contraseña</label>
            <input 
              type="password"
              className="form-control"
              id="confirm_password"
              name="confirm_password"
              value={formData.confirm_password}
              onChange={handleChange}
              required
            />
          </div>
          <button type="submit" className="btn btn-primary btn-block">Registrar</button>
        </form>
      </div>
    </div>
  );
};

export default RegistroAlumno;
