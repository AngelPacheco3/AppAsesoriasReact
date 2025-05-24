import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const NuevaAsesoria = () => {
  const [asesoria, setAsesoria] = useState({
    descripcion: '',
    costo: '',
    max_alumnos: '',
    temas: '',
    meet_link: ''
  });
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    setAsesoria({
      ...asesoria,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    axios.post('/api/nueva_asesoria', asesoria)
      .then(response => {
        alert('Asesoría creada correctamente');
        navigate('/dashboard_maestro');
      })
      .catch(() => setError('Error al crear la asesoría.'));
  };

  return (
    <div className="container-fluid">
      <div className="login-box">
        <h2 className="text-center mb-4">Nueva Asesoría</h2>
        {error && <p className="text-danger text-center">{error}</p>}
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="descripcion">Descripción</label>
            <input 
              type="text"
              className="form-control"
              id="descripcion"
              name="descripcion"
              value={asesoria.descripcion}
              onChange={handleChange}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="costo">Costo</label>
            <input 
              type="number"
              className="form-control"
              id="costo"
              name="costo"
              value={asesoria.costo}
              onChange={handleChange}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="max_alumnos">Máximo de Alumnos</label>
            <input 
              type="number"
              className="form-control"
              id="max_alumnos"
              name="max_alumnos"
              value={asesoria.max_alumnos}
              onChange={handleChange}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="temas">Temas</label>
            <input 
              type="text"
              className="form-control"
              id="temas"
              name="temas"
              value={asesoria.temas}
              onChange={handleChange}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="meet_link">Enlace de Google Meet</label>
            <input 
              type="url"
              className="form-control"
              id="meet_link"
              name="meet_link"
              value={asesoria.meet_link}
              onChange={handleChange}
            />
          </div>
          <button type="submit" className="btn btn-primary btn-block">Crear Asesoría</button>
        </form>
      </div>
    </div>
  );
};


export default NuevaAsesoria;
