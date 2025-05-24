import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';

const EditarAsesoria = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [asesoria, setAsesoria] = useState({
    descripcion: '',
    costo: '',
    max_alumnos: '',
    temas: '',
    meet_link: '',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  // Cargar los datos actuales de la asesoría (GET)
  useEffect(() => {
    axios.get(`/api/editar_asesoria/${id}`, { withCredentials: true })
      .then(response => {
        // Supongamos que el endpoint GET devuelve { asesoria: {...} }
        // Si no, puedes ajustarlo a response.data según como envíe los datos tu API
        setAsesoria(response.data.asesoria || response.data);
        setLoading(false);
      })
      .catch(err => {
        setError('Error al cargar la asesoría.');
        setLoading(false);
      });
  }, [id]);

  const handleChange = (e) => {
    setAsesoria({
      ...asesoria,
      [e.target.name]: e.target.value,
    });
  };

  // Enviar cambios utilizando el método PUT
  const handleSubmit = (e) => {
    e.preventDefault();
    axios.put(`/api/editar_asesoria/${id}`, asesoria, { withCredentials: true })
      .then(response => {
        alert(response.data.message);
        navigate(`/ver_detalle_asesoria_maestro/${id}`);
      })
      .catch(() => setError('Error al actualizar la asesoría.'));
  };

  if (loading) return <p className="text-center mt-4">Cargando...</p>;
  if (error) return <p className="text-danger text-center mt-4">{error}</p>;

  return (
    <div className="container-fluid">
      <div style={{ height: '50px' }}></div>
      <button 
        className="btn btn-custom btn-back"
        style={{ position: 'absolute', top: '10px', left: '10px' }}
        onClick={() => navigate(-1)}
      >
        ←
      </button>
      
      <div className="login-box mt-5">
        <h2 className="text-center mb-4">Editar Asesoría</h2>
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
              required
            />
          </div>
          <button type="submit" className="btn btn-primary btn-block">
            Guardar Cambios
          </button>
        </form>
      </div>
    </div>
  );
};

export default EditarAsesoria;
