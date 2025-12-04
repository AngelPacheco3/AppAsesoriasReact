import axios from 'axios';
import { jwtDecode } from 'jwt-decode';

// --- ✅ CORRECCIÓN: La baseURL NUNCA debe incluir /api ---
// axios.defaults.baseURL = process.env.REACT_APP_API_URL; // ELIMINADA

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

// --- FUNCIÓN PARA OBTENER DATOS DEL TOKEN ---
export const getUserData = () => {
  const token = getJWTToken();
  if (!token) {
    return null; // No hay usuario logueado
  }
  try {
    // Decodificar el token para obtener el payload (id, rol, nombre, etc.)
    const decoded = jwtDecode(token);
    return decoded;
  } catch (error) {
    console.error("Token inválido o expirado:", error);
    removeJWTToken(); // Limpiar token inválido
    return null;
  }
};
// --- FIN DE LA FUNCIÓN ---


// Función para obtener el token CSRF del backend
const fetchCSRFToken = async () => {
  try {
    // --- ✅ CORRECCIÓN: Añadir /api/ aquí ---
    // Esta llamada no es relativa a un componente, debe ser absoluta
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
    
    // Si el error es por token JWT expirado o inválido (401)
    if (error.response?.status === 401 && !originalRequest._retry) {
       originalRequest._retry = true; // Prevenir bucles infinitos
       
       console.warn("Token expirado o inválido. Redirigiendo al login.");
       removeJWTToken(); // Eliminar token expirado
       
       // Redireccionar al login
       // Usamos window.location para forzar recarga completa y limpiar estado
       window.location.href = '/#/login'; // Corregido para HashRouter
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
    
    return Promise.reject(error);
  }
);

export const isAuthenticated = () => {
  return !!getJWTToken();
};

export const verifyToken = async () => {
  try {
    // --- ✅ CORRECCIÓN: Añadir /api/ ---
    const response = await axios.get('/api/verify-token'); // Llama a /api/verify-token
    return response.data;
  } catch (error) {
    removeJWTToken();
    return { valid: false };
  }
};

export const refreshCSRFToken = fetchCSRFToken;

export default axios;