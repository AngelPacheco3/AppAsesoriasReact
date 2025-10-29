import React, { useState, useEffect } from 'react';
// Asegúrate de que esta ruta '../axiosConfig' sea correcta para tu estructura de carpetas
import axios, { removeJWTToken } from '../axiosConfig'; 
import { useNavigate } from 'react-router-dom';

const DashboardAlumno = () => {
  const [asesorias, setAsesorias] = useState([]);
  const [error, setError] = useState('');
  const [actualizar, setActualizar] = useState(false); // Estado para forzar actualización
  const navigate = useNavigate();

  // Función para cargar asesorías
  const cargarAsesorias = () => {
    axios.get('/api/dashboard_alumno')
      .then(response => {
        console.log("Asesorías disponibles recibidas:", response.data);
        // Asegurarse de que response.data.asesorias es un array
        setAsesorias(Array.isArray(response.data.asesorias) ? response.data.asesorias : []);
        setError(''); // Limpiar errores previos
      })
      .catch(err => {
        console.error("Error al cargar asesorías:", err);
        setError('Error al cargar las asesorías disponibles.');
        setAsesorias([]); // Limpiar asesorías en caso de error
      });
  };

  // Cargar asesorías al montar y al actualizar
  useEffect(() => {
    cargarAsesorias();
  }, [actualizar]); // Se ejecuta cuando 'actualizar' cambia

  // Función de Logout (sin cambios respecto a tu código anterior)
  const handleLogout = async () => {
    if (window.confirm("¿Deseas cerrar sesión?")) {
      try {
        await axios.post('/api/logout', {});
        removeJWTToken();
        console.log("Sesión cerrada correctamente.");
        setAsesorias([]);
        navigate('/login');
      } catch (err) {
        console.error("Error al cerrar sesión:", err);
        removeJWTToken(); // Asegurar limpieza incluso con error
        navigate('/login');
      }
    }
  };

  // Navegar a ver detalles
  const handleVerDetalles = (id) => {
    navigate(`/ver_detalle_asesoria/${id}`); // O la ruta correcta que uses
  };

  return (
    <>
      {/* Navbar */}
      <nav className="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
        <span className="navbar-brand mx-auto">Asesorías Alumnos</span>
        <div className="collapse navbar-collapse">
          <ul className="navbar-nav ml-auto">
            <li className="nav-item">
              <button className="btn btn-light" onClick={handleLogout}>Cerrar Sesión</button>
            </li>
          </ul>
        </div>
      </nav>

      {/* Contenedor Principal */}
      <div className="container mt-4">
        <div className="card shadow-lg">
          <div className="card-body">
            <h2 className="text-center mb-4">Asesorías Disponibles</h2>

            {error ? (
              <p className="text-danger text-center">{error}</p>
            ) : (
              // --- ✅ INICIO DE LA MODIFICACIÓN ---
              // Envolver la tabla con table-responsive
              <div className="table-responsive">
                <table className="table table-striped table-hover">
                  <thead className="thead-dark">
                    <tr>
                      <th>Descripción</th>
                      <th>Costo</th>
                      <th>Máximo de Alumnos</th>
                      <th>Temas</th>
                      <th>Maestro</th>
                      <th>Acciones</th>
                    </tr>
                  </thead>
                  <tbody>
                    {asesorias.length === 0 ? (
                      <tr>
                        <td colSpan="6" className="text-center">No hay asesorías disponibles en este momento.</td>
                      </tr>
                    ) : (
                      asesorias.map(({ id, descripcion, costo, max_alumnos, temas, maestro }) => (
                        <tr key={id}>
                          <td>{descripcion}</td>
                          <td>${costo ? costo.toFixed(2) : 'N/A'}</td> {/* Asegurar que costo sea número */}
                          <td>{max_alumnos}</td>
                          <td>{temas}</td>
                          <td>{maestro?.nombre || 'N/A'}</td> {/* Acceso seguro al nombre */}
                          <td>
                            <button
                              className="btn btn-info btn-sm"
                              onClick={() => handleVerDetalles(id)}
                            >
                              Ver Detalles
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
              // --- ✅ FIN DE LA MODIFICACIÓN ---
            )}

            {/* Botón para actualizar manualmente */}
            <div className="text-center mt-3">
              <button className="btn btn-secondary" onClick={() => setActualizar(!actualizar)}>
                🔄 Actualizar Asesorías
              </button>
            </div>

          </div> {/* Fin card-body */}
        </div> {/* Fin card */}
      </div> {/* Fin container */}
    </>
  );
};

export default DashboardAlumno;
