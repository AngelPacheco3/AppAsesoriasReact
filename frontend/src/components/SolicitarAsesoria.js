import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';

const SolicitarAsesoria = () => {
  const { id } = useParams(); // Obtiene el ID de la asesoría desde la URL
  const navigate = useNavigate();
  const [asesoria, setAsesoria] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get(`/api/ver_asesoria/${id}`)
      .then(response => {
        setAsesoria(response.data);
        setLoading(false);
      })
      .catch(() => {
        setError('Error al cargar los datos de la asesoría.');
        setLoading(false);
      });
  }, [id]);

  const handleSolicitud = (e) => {
    e.preventDefault();
    axios.post(`/api/solicitar_asesoria/${id}`)
      .then(() => {
        alert('Inscripción realizada con éxito.');
        navigate('/dashboard_alumno');
      })
      .catch(() => setError('Error al solicitar la asesoría.'));
  };

  if (loading) return <p className="text-center mt-4">Cargando datos de la asesoría...</p>;
  if (error) return <p className="text-danger text-center mt-4">{error}</p>;

  return (
    <div className="container mt-5">
      <h2>Solicitar Asesoría</h2>
      {asesoria && (
        <>
          <p><strong>Descripción:</strong> {asesoria.descripcion}</p>
          <p><strong>Costo:</strong> {asesoria.costo}</p>
          <p><strong>Máx. Alumnos:</strong> {asesoria.max_alumnos}</p>
          <form onSubmit={handleSolicitud}>
            <button type="submit" className="btn btn-primary">Inscribirse en la Asesoría</button>
          </form>
        </>
      )}
    </div>
  );
};

export default SolicitarAsesoria;
