// axiosConfig.js - Versión corregida con CSRF
import axios from 'axios';

// Configurar axios con credenciales
axios.defaults.withCredentials = true;

// Función para obtener CSRF token
const getCSRFToken = () => {
  // Buscar el token en las cookies
  const name = 'csrf_token=';
  const decodedCookie = decodeURIComponent(document.cookie);
  const ca = decodedCookie.split(';');
  for(let i = 0; i < ca.length; i++) {
    let c = ca[i];
    while (c.charAt(0) === ' ') {
      c = c.substring(1);
    }
    if (c.indexOf(name) === 0) {
      return c.substring(name.length, c.length);
    }
  }
  return null;
};

// Interceptor para agregar CSRF token a todas las peticiones POST/PUT/DELETE
axios.interceptors.request.use(
  (config) => {
    // Solo agregar CSRF token para métodos que lo necesitan
    if (['post', 'put', 'delete', 'patch'].includes(config.method?.toLowerCase())) {
      const csrfToken = getCSRFToken();
      if (csrfToken) {
        config.headers['X-CSRFToken'] = csrfToken;
      }
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Interceptor para manejar errores de respuesta
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Redireccionar al login si no está autenticado
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default axios;