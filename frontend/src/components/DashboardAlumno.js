import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const DashboardAlumno = () => {
  const [asesorias, setAsesorias] = useState([]);
  const [error, setError] = useState('');
  const [actualizar, setActualizar] = useState(false); // ✅ Estado para forzar actualización
  const navigate = useNavigate();

  // Función para cargar asesorías (usada en useEffect)
  const cargarAsesorias = () => {
    axios.get('/api/dashboard_alumno', { withCredentials: true })
      .then(response => {
        console.log("Datos actualizados recibidos:", response.data);  // 🔍 Depuración
        setAsesorias(Array.isArray(response.data.asesorias) ? response.data.asesorias : []);
      })
      .catch(err => {
        console.error("Error al cargar asesorías:", err);
        setError('Error al cargar las asesorías.');
      });
  };

  // Cargar asesorías al montar el componente y cuando se cree una nueva asesoría
  useEffect(() => {
    cargarAsesorias();
  }, [actualizar]); // ✅ Se ejecuta cada vez que `actualizar` cambia

  // Manejo del cierre de sesión
  const handleLogout = async () => {
    if (window.confirm("¿Deseas cerrar sesión?")) {
      try {
        await axios.post('/api/logout', {}, { withCredentials: true });  // ✅ Cierra sesión en Flask
        console.log("Sesión cerrada correctamente.");  // 🔍 Depuración
        setAsesorias([]);  // ✅ Limpia asesorías al cerrar sesión
        navigate('/login');  // ✅ Redirige al login
      } catch (err) {
        console.error("Error al cerrar sesión:", err);
      }
    }
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

      {/* Contenedor principal */}
      <div className="container mt-4">
        <div className="card shadow-lg">
          <div className="card-body">
            <h2 className="text-center mb-4">Asesorías Disponibles</h2>

            {error ? (
              <p className="text-danger text-center">{error}</p>
            ) : (
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
                      <td colSpan="6" className="text-center">No hay asesorías disponibles.</td>
                    </tr>
                  ) : (
                    asesorias.map(({ id, descripcion, costo, max_alumnos, temas, maestro }) => (
                      <tr key={id}>
                        <td>{descripcion}</td>
                        <td>{costo}</td>
                        <td>{max_alumnos}</td>
                        <td>{temas}</td>
                        <td>{maestro?.nombre}</td>
                        <td>
                          <button 
                            className="btn btn-info btn-sm"
                            onClick={() => navigate(`/ver_asesoria/${id}`)}  // ✅ Redirige a VerAsesoria.js
                          >
                            Ver Detalles
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            )}

            {/* Botón para actualizar manualmente */}
            <div className="text-center mt-3">
              <button className="btn btn-secondary" onClick={() => setActualizar(!actualizar)}>
                🔄 Actualizar Asesorías
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default DashboardAlumno;
