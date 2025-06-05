import axios from 'axios';

// Configurar axios con credenciales
axios.defaults.withCredentials = true;

// Variable para almacenar el token CSRF
let csrfToken = null;

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

// Obtener el token al cargar la aplicación
fetchCSRFToken();

// Interceptor para agregar CSRF token a todas las peticiones que lo necesitan
axios.interceptors.request.use(
  async (config) => {
    // Solo agregar CSRF token para métodos que modifican datos
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
    // Si el error es por token CSRF inválido, obtener nuevo token y reintentar
    if (error.response?.status === 400 && error.response?.data?.error?.includes('CSRF')) {
      const originalRequest = error.config;
      
      // Evitar bucle infinito
      if (!originalRequest._retry) {
        originalRequest._retry = true;
        
        // Obtener nuevo token
        await fetchCSRFToken();
        
        // Actualizar el header con el nuevo token
        if (csrfToken) {
          originalRequest.headers['X-CSRFToken'] = csrfToken;
        }
        
        // Reintentar la petición
        return axios(originalRequest);
      }
    }
    
    // Redireccionar al login si no está autenticado
    if (error.response?.status === 401) {
      window.location.href = '/login';
    }
    
    return Promise.reject(error);
  }
);

// Exportar función para refrescar token manualmente si es necesario
export const refreshCSRFToken = fetchCSRFToken;

export default axios;
