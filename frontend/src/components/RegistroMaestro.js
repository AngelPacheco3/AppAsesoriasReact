import React, { useState } from 'react';
//import axios from 'axios';
import axios from '../axiosConfig';
import { useNavigate } from 'react-router-dom';

const RegistroMaestro = () => {
  const [formData, setFormData] = useState({
    nombre: '',
    email: '',
    password: '',
    confirm_password: '',
    especializacion: '',
    foto: null,
    edad: '',
    nivel: 'licenciatura'
  });
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
  };

  const handleFileChange = (e) => {
    setFormData({
      ...formData,
      foto: e.target.files[0]
    });
  };

  const handleSubmit = (e) => {
    e.preventDefault();

    if (formData.password !== formData.confirm_password) {
      setError('Las contraseñas no coinciden.');
      return;
    }

    const data = new FormData();
    for (const key in formData) {
      data.append(key, formData[key]);
    }

    axios.post('/api/registro_maestro', data, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
      .then(() => {
        alert('Registro exitoso.');
        navigate('/login');
      })
      .catch(() => setError('Error al registrar maestro.'));
  };

  return (
    <div className="container-fluid">
      <button 
        className="btn btn-custom btn-back"
        onClick={() => navigate('/crear_usuario')}
        style={{ position: 'absolute', top: '10px', left: '10px' }}
      >
        ←
      </button>

      <div className="login-box mt-5">
        <h2 className="text-center mb-4">Registro de Maestro</h2>
        {error && <p className="text-danger text-center">{error}</p>}
        <form onSubmit={handleSubmit} encType="multipart/form-data">
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
          <div className="form-group">
            <label htmlFor="especializacion">Áreas de Especialización</label>
            <input 
              type="text"
              className="form-control"
              id="especializacion"
              name="especializacion"
              value={formData.especializacion}
              onChange={handleChange}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="foto">Fotografía</label>
            <input 
              type="file"
              className="form-control-file"
              id="foto"
              name="foto"
              onChange={handleFileChange}
            />
          </div>
          <div className="form-group">
            <label htmlFor="edad">Edad</label>
            <input 
              type="number"
              className="form-control"
              id="edad"
              name="edad"
              value={formData.edad}
              onChange={handleChange}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="nivel">Nivel de Estudios</label>
            <select 
              className="form-control"
              id="nivel"
              name="nivel"
              value={formData.nivel}
              onChange={handleChange}
            >
              <option value="licenciatura">Licenciatura</option>
              <option value="maestria">Maestría</option>
              <option value="doctorado">Doctorado</option>
            </select>
          </div>
          <button type="submit" className="btn btn-primary btn-block">Registrarse</button>
        </form>
      </div>
    </div>
  );
};

export default RegistroMaestro;
