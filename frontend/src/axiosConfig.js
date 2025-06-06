// axiosConfig.js - Versión con JWT y CSRF
import axios from 'axios';

// Configurar axios con credenciales
axios.defaults.withCredentials = true;

// Variables para tokens
let csrfToken = null;

// Función para obtener JWT del localStorage
const getJWTToken = () => {
  return localStorage.getItem('jwt_token');
};

// Función para guardar JWT
export const saveJWTToken = (token) => {
  localStorage.setItem('jwt_token', token);
};

// Función para eliminar JWT (logout)
export const removeJWTToken = () => {
  localStorage.removeItem('jwt_token');
};

// Función para obtener el token CSRF del backend
const fetchCSRFToken = async () => {
  try {
    const response = await axios.get('/api/csrf-token');
    csrfToken = response.data.csrf_token;
    return csrfToken;
  } catch (error) {
    console.error('Error obteniendo CSRF token:', error);
    return null;
  }
};

// Obtener el token CSRF al cargar la aplicación
fetchCSRFToken();

// Interceptor para agregar JWT y CSRF token a las peticiones
axios.interceptors.request.use(
  async (config) => {
    // Agregar JWT token si existe
    const jwtToken = getJWTToken();
    if (jwtToken) {
      config.headers['Authorization'] = `Bearer ${jwtToken}`;
    }
    
    // Agregar CSRF token para métodos que modifican datos
    if (['post', 'put', 'delete', 'patch'].includes(config.method?.toLowerCase())) {
      // Si no tenemos token, obtenerlo primero
      if (!csrfToken) {
        await fetchCSRFToken();
      }
      
      // Agregar el token al header
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
  async (error) => {
    const originalRequest = error.config;
    
    // Si el error es por token JWT expirado
    if (error.response?.status === 401 && error.response?.data?.error === 'Token expired') {
      // Eliminar token expirado
      removeJWTToken();
      
      // Redireccionar al login
      window.location.href = '/login';
      return Promise.reject(error);
    }
    
    // Si el error es por CSRF token inválido
    if (error.response?.status === 400 && error.response?.data?.error?.includes('CSRF')) {
      if (!originalRequest._retry) {
        originalRequest._retry = true;
        
        // Obtener nuevo token CSRF
        await fetchCSRFToken();
        
        // Actualizar el header con el nuevo token
        if (csrfToken) {
          originalRequest.headers['X-CSRFToken'] = csrfToken;
        }
        
        // Reintentar la petición
        return axios(originalRequest);
      }
    }
    
    // Si es error 401 genérico (no autenticado)
    if (error.response?.status === 401) {
      removeJWTToken();
      window.location.href = '/login';
    }
    
    return Promise.reject(error);
  }
);

// Función para verificar si el usuario está autenticado
export const isAuthenticated = () => {
  return !!getJWTToken();
};

// Función para verificar el token con el servidor
export const verifyToken = async () => {
  try {
    const response = await axios.get('/api/verify-token');
    return response.data;
  } catch (error) {
    removeJWTToken();
    return { valid: false };
  }
};

// Exportar función para refrescar token CSRF manualmente si es necesario
export const refreshCSRFToken = fetchCSRFToken;

export default axios;
