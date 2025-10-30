import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
// Asegúrate de que la ruta sea correcta
import { getUserData, removeJWTToken } from '../axiosConfig'; 

/*
  Este componente protege las rutas:
  1. Si no estás logueado, te envía a /login.
  2. Si estás logueado pero intentas acceder a una ruta de otro rol, te envía a tu dashboard correcto.
*/
const ProtectedRoute = ({ children, roleRequired }) => {
  const location = useLocation();
  const userData = getUserData(); // Obtiene { id, rol, ... } del token

  if (!userData) {
    // Caso 1: Usuario no está logueado
    // Redirigir a login, guardando la ruta que intentó visitar
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Verificar si el token ha expirado (el campo 'exp' está en segundos)
  if (userData.exp * 1000 < Date.now()) {
      console.warn("Token expirado detectado por el cliente.");
      removeJWTToken(); // Limpiar token expirado
      return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (roleRequired && userData.rol !== roleRequired) {
    // Caso 2: Usuario logueado, pero rol incorrecto
    console.warn(`Acceso denegado: Usuario con rol '${userData.rol}' intentó acceder a ruta para '${roleRequired}'`);
    
    // Redirigir al usuario a su dashboard correcto
    const homeDashboard = userData.rol === 'maestro' ? '/dashboard_maestro' : '/dashboard_alumno';
    
    return <Navigate to={homeDashboard} replace />;
  }

  // Caso 3: Usuario logueado y con el rol correcto (o no se requiere rol específico)
  return children;
};

export default ProtectedRoute;