import React, { useState, useEffect } from 'react';
import axios, { removeJWTToken } from '../axiosConfig';  // 🔴 CAMBIO: Importar removeJWTToken
import { useNavigate } from 'react-router-dom';

const DashboardMaestro = () => {
  const [asesorias, setAsesorias] = useState([]);
  const [error, setError] = useState('');
  const [actualizar, setActualizar] = useState(false);
  const navigate = useNavigate();

  // Función para cargar asesorías (sin cambios)
  const cargarAsesorias = () => {
    axios.get('/api/dashboard_maestro')
      .then(response => {
        console.log("Datos actualizados recibidos:", response.data);
        setAsesorias(Array.isArray(response.data.asesorias) ? response.data.asesorias : []);
      })
      .catch(err => {
        console.error("Error al cargar asesorías:", err);
        setError('Error al cargar las asesorías.');
      });
  };

  // Cargar asesorías al montar el componente y cuando se crea o elimina una asesoría
  useEffect(() => {
    cargarAsesorias();
  }, [actualizar]);

  // 🔴 CAMBIO: Función handleLogout actualizada para JWT
  const handleLogout = async () => {
    if (window.confirm("¿Deseas cerrar sesión?")) {
      try {
        // 1. Llamar al endpoint de logout
        await axios.post('/api/logout', {});
        
        // 2. IMPORTANTE: Eliminar el JWT token del localStorage
        removeJWTToken();
        
        console.log("Sesión cerrada correctamente.");
        
        // 3. Limpiar el estado local
        setAsesorias([]);
        
        // 4. Redirigir al login
        navigate('/login');
      } catch (err) {
        console.error("Error al cerrar sesión:", err);
        
        // IMPORTANTE: Incluso si hay error, eliminar token y redirigir
        removeJWTToken();
        navigate('/login');
      }
    }
  };

  // Manejo de eliminación de asesorías (sin cambios)
  const handleDelete = (id) => {
    if (window.confirm("¿Estás seguro de que quieres eliminar esta asesoría?")) {
      axios.delete(`/api/borrar_asesoria/${id}`)
        .then(() => {
          console.log(`Asesoría ${id} eliminada correctamente.`);
          setActualizar(!actualizar);
        })
        .catch(() => alert("Error al eliminar la asesoría."));
    }
  };

  return (
    <>
      {/* Navbar */}
      <nav className="navbar navbar-expand-lg navbar-dark bg-primary mb-4">
        <span className="navbar-brand mx-auto">Asesorías Maestros</span>
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
            <h2 className="text-center mb-4">Tus Asesorías</h2>

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
                    <th>Registrados</th>
                    <th>Total Pagado</th>
                    <th>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {asesorias.length === 0 ? (
                    <tr>
                      <td colSpan="7" className="text-center">No has creado asesorías.</td>
                    </tr>
                  ) : (
                    asesorias.map(({ id, descripcion, costo, max_alumnos, temas, registrados, total_pagado }) => (
                      <tr key={id}>
                        <td>{descripcion}</td>
                        <td>{costo}</td>
                        <td>{max_alumnos}</td>
                        <td>{temas}</td>
                        <td>{registrados}</td>
                        <td>${total_pagado.toFixed(2)}</td>
                        <td>
                          <button 
                            className="btn btn-info btn-sm"
                            onClick={() => navigate(`/ver_detalle_asesoria_maestro/${id}`)}
                          >
                            Ver Detalles
                          </button>

                          <button 
                            className="btn btn-danger btn-sm ms-2"
                            onClick={() => handleDelete(id)}
                          >
                            Eliminar
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

            <button 
              className="btn btn-success btn-block mt-4"
              onClick={() => navigate('/nueva_asesoria')}
            >
              Agregar Nueva Asesoría
            </button>
          </div>
        </div>
      </div>
    </>
  );
};

export default DashboardMaestro;
