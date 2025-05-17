import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';

const VerAsesoria = () => {
  const { id } = useParams(); // Se asume que la URL es algo como /ver_asesoria/:id
  const navigate = useNavigate();

  // Estados para almacenar la data, carga y errores
  const [asesoriaData, setAsesoriaData] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  // Cargar datos de la asesoría
  useEffect(() => {
    const fetchData = async () => {
      try {
        // Se espera que el endpoint retorne la estructura que incluya:
        // { asesoria, maestro, alumnos, registrado, pagado }
        const response = await axios.get(`/api/ver_detalle_asesoria/${id}`, { withCredentials: true });
        console.log("Respuesta de la API:", response.data);
        setAsesoriaData(response.data);
      } catch (err) {
        setError(
          err.response && err.response.data
            ? err.response.data.error
            : 'Error al cargar la asesoría'
        );
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [id]);

  if (loading) {
    return (
      <div className="container mt-4">
        <p className="text-center">Cargando información...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mt-4">
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      </div>
    );
  }

  if (!asesoriaData) {
    return (
      <div className="container mt-4">
        <p className="text-center">No se encontraron datos para esta asesoría.</p>
      </div>
    );
  }

  // Desestructura la respuesta del API
  const { asesoria, maestro, alumnos, registrado, pagado } = asesoriaData;

  return (
    <div className="container mt-4">
      {/* Barra de navegación */}
      <nav className="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
        <button
          className="btn btn-outline-light"
          onClick={() => navigate('/dashboard_alumno')}
        >
          &larr;
        </button>
        <a className="navbar-brand mx-auto" href="#">
          Detalles de la Asesoría
        </a>
      </nav>

      <div className="card shadow-lg">
        <div className="card-header bg-primary text-white text-center">
          <h2 className="mb-0">Detalle de Asesoría</h2>
        </div>
        <div className="card-body">
          <div className="row mb-3">
            {/* Columna de detalles de la asesoría */}
            <div className="col-md-6">
              <p><strong>ID:</strong> {asesoria.id}</p>
              <p><strong>Descripción:</strong> {asesoria.descripcion}</p>
              <p><strong>Costo:</strong> {asesoria.costo}</p>
              <p><strong>Máximo de Alumnos:</strong> {asesoria.max_alumnos}</p>
              <p><strong>Temas:</strong> {asesoria.temas}</p>
            </div>
            {/* Columna de datos del maestro */}
            <div className="col-md-6 text-center">
              <p><strong>Detalle del Maestro</strong></p>
              <p><strong>ID:</strong> {maestro.id}</p>
              <p><strong>Nombre:</strong> {maestro.nombre}</p>
              <p><strong>Email:</strong> {maestro.email}</p>
              {maestro.foto && (
                <img
                  src={`/static/profile_pics/${maestro.foto}`}
                  alt="Foto del Maestro"
                  className="img-fluid rounded-circle"
                  style={{ maxWidth: '150px' }}
                />
              )}
            </div>
          </div>
          <hr />

          {/* Lista de alumnos registrados */}
          <h3 className="mb-3">Alumnos Registrados</h3>
          {alumnos && alumnos.length > 0 ? (
            <ul className="list-group mb-3">
              {alumnos.map((alumno) => (
                <li key={alumno.id} className="list-group-item">
                  {alumno.nombre} ({alumno.email})
                </li>
              ))}
            </ul>
          ) : (
            <p>No hay alumnos registrados en esta asesoría.</p>
          )}

          {/* Control de visualización según registro y pago */}
          {registrado ? (
            pagado ? (
              <div className="alert alert-success mt-3">
                <strong>Enlace de Google Meet:</strong>{' '}
                <a href={asesoria.meet_link} target="_blank" rel="noopener noreferrer">
                  {asesoria.meet_link}
                </a>
              </div>
            ) : (
              <div className="alert alert-warning mt-3">
                Ya te has registrado en esta asesoría, pero aún falta realizar el pago.
              </div>
            )
          ) : (
            <div className="mt-3">
              <button
                className="btn btn-primary btn-block"
                onClick={() => navigate(`/pago_asesoria/${asesoria.id}`)}
              >
                Pagar y Obtener Enlace de Meet
              </button>
            </div>
          )}
        </div>
        <div className="card-footer text-center">
          <button
            className="btn btn-primary"
            onClick={() => window.history.back()}
          >
            &larr; Regresar
          </button>
        </div>
      </div>
    </div>
  );
};

export default VerAsesoria;
