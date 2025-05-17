import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';

const VerDetalleAsesoria = () => {
  const { id } = useParams(); // Obtiene el ID de la asesoría desde la URL
  const navigate = useNavigate();

  // Estado único para almacenar la respuesta de la API
  const [data, setData] = useState(null);
  // Estado para manejo de error y carga
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  // Cargar datos de la asesoría del maestro
  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get(`/api/ver_detalle_asesoria_maestro/${id}`, { withCredentials: true });
        console.log('Detalles obtenidos:', response.data);
        setData(response.data);
      } catch (err) {
        console.error('Error al cargar asesoría:', err);
        setError(err.response?.data?.error || 'Error al cargar la asesoría.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, [id]);

  // Mientras se carga la información
  if (isLoading) {
    return (
      <div className="container mt-4">
        <p className="text-center">Cargando detalles...</p>
      </div>
    );
  }

  // Si hay error o no se obtuvo datos
  if (error || !data) {
    return (
      <div className="container mt-4">
        <p className="text-center text-danger">{error || 'No se encontraron detalles de la asesoría.'}</p>
      </div>
    );
  }

  // Desestructuramos la data obtenida
  const { asesoria, maestro, alumnos } = data;
  const totalPagado = asesoria?.total_pagado || 0.0;

  return (
    <div className="container mt-4">
      {/* Barra de navegación similar a tu plantilla Jinja */}
      <nav className="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
        <button
          className="btn btn-outline-light"
          onClick={() => navigate('/dashboard_maestro')}
        >
          &larr;
        </button>
        <a className="navbar-brand mx-auto" href="#">
          Detalles de la Asesoría
        </a>
      </nav>

      <div className="card shadow-lg">
        <div className="card-body">
          <h2 className="text-center mb-4">{asesoria.descripcion}</h2>
          <div className="row mb-3">
            <div className="col-md-6">
              <p><strong>Costo:</strong> {asesoria.costo}</p>
              <p><strong>Máximo de Alumnos:</strong> {asesoria.max_alumnos}</p>
              <p><strong>Temas:</strong> {asesoria.temas}</p>
            </div>
            <div className="col-md-6 text-center">
              <p><strong>Maestro:</strong> {maestro.nombre}</p>
              {maestro.foto ? (
                <img
                  src={maestro.foto}
                  alt="Foto del Maestro"
                  className="img-fluid rounded-circle"
                  style={{ maxWidth: "150px" }}
                />
              ) : null}
            </div>
          </div>

          <h4 className="mb-3">Alumnos Registrados:</h4>
          <ul className="list-group mb-3">
            {alumnos && alumnos.length > 0 ? (
              alumnos.map((alumno) => (
                <li key={alumno.id} className="list-group-item">
                  {alumno.nombre}
                </li>
              ))
            ) : (
              <li className="list-group-item">No hay alumnos registrados aún.</li>
            )}
          </ul>

          <p>
            <strong>Total Generado:</strong> ${totalPagado.toFixed(2)}
          </p>
          <p>
            <strong>Enlace de Google Meet:</strong>{" "}
            <a href={asesoria.meet_link} target="_blank" rel="noopener noreferrer">
              {asesoria.meet_link}
            </a>
          </p>
          <button
            className="btn btn-warning btn-block mt-4"
            onClick={() => navigate(`/editar_asesoria/${asesoria.id}`)}
          >
            Editar Asesoría
          </button>
        </div>
      </div>
    </div>
  );
};

export default VerDetalleAsesoria;
