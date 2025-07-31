'use strict';

const CONSTANTS = {
    POLLING_INTERVALS: {
        UPS: 5000,
        DEVICES: 5000,
        ANALYTICS: 5000,
        LOGS: 7000
    },
    TOAST_DURATION: 5000,
    TOAST_FADE_DURATION: 200,
    DEBOUNCE_DELAY: 300,
    VALIDATION: {
        IP_PATTERN: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
        MAC_PATTERN: /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/,
        CIDR_PATTERN: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$/
    }
};

const Utils = {
    toggleMobileSidebar() {
        const sidebar = document.getElementById('mobile-sidebar');
        if (sidebar) {
            sidebar.classList.toggle('-translate-x-full');
        }
    },

    getCSRFToken() {
        const metaToken = document.querySelector('meta[name="csrf-token"]');
        return metaToken ? metaToken.getAttribute('content') : null;
    },

    debounce(func, delay = CONSTANTS.DEBOUNCE_DELAY) {
        let timeoutId;
        return function (...args) {
            clearTimeout(timeoutId);
            timeoutId = setTimeout(() => func.apply(this, args), delay);
        };
    },

    throttle(func, limit) {
        let inThrottle;
        return function (...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    },

    setTextContent(element, content) {
        if (element && typeof content === 'string') {
            element.textContent = content;
        }
    },

    validateIP(ip) {
        return CONSTANTS.VALIDATION.IP_PATTERN.test(ip);
    },

    validateMAC(mac) {
        return CONSTANTS.VALIDATION.MAC_PATTERN.test(mac);
    },

    validateCIDR(cidr) {
        return CONSTANTS.VALIDATION.CIDR_PATTERN.test(cidr);
    },

    normalizeMac(mac) {
        if (!mac) return '';
        return mac.toUpperCase().replace(/-/g, ':');
    },

    handleError(error, context = 'Unknown') {
        console.error(`[${context}] Error:`, error);
        return {
            success: false,
            message: error.message || 'An unexpected error occurred',
            context
        };
    },

    async safeAsync(asyncFn, context = 'Async operation') {
        try {
            return await asyncFn();
        } catch (error) {
            return this.handleError(error, context);
        }
    },

    formatTime(timestamp) {
        try {
            return new Date(timestamp * 1000).toLocaleTimeString([], { 
                hour: '2-digit', 
                minute: '2-digit' 
            });
        } catch (error) {
            return 'Invalid time';
        }
    },

    sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        return input.trim().replace(/[<>]/g, '');
    },

    isLibraryLoaded(libraryName) {
        switch(libraryName) {
            case 'Chart':
                return typeof window.Chart !== 'undefined';
            case 'Sortable':
                return typeof window.Sortable !== 'undefined';
            case 'Alpine':
                return typeof window.Alpine !== 'undefined';
            default:
                return false;
        }
    },

    createChart(ctx, config) {
        if (!this.isLibraryLoaded('Chart')) {
            console.error('Chart.js is not loaded');
            return null;
        }
        try {
            return new Chart(ctx, config);
        } catch (error) {
            console.error('Failed to create chart:', error);
            return null;
        }
    },

    generateId() {
        return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }
};

const ToastManager = {
    nextId: 1,
    alpineComponent: null,

    setAlpineComponent(component) {
        this.alpineComponent = component;
    },

    show(message, type = 'info', duration = CONSTANTS.TOAST_DURATION) {
        const id = this.nextId++;
        const toast = {
            id,
            message: Utils.sanitizeInput(message),
            type,
            visible: true,
            createdAt: Date.now()
        };

        if (this.alpineComponent && this.alpineComponent.toasts) {
            this.alpineComponent.toasts.push(toast);
            
            setTimeout(() => {
                this.remove(id);
            }, duration);
        } else {
            console.warn('Toast:', message, `[${type}]`);
        }

        return id;
    },

    remove(id) {
        if (this.alpineComponent && this.alpineComponent.toasts) {
            const index = this.alpineComponent.toasts.findIndex(t => t.id === id);
            if (index > -1) {
                this.alpineComponent.toasts[index].visible = false;
                setTimeout(() => {
                    this.alpineComponent.toasts.splice(index, 1);
                }, CONSTANTS.TOAST_FADE_DURATION);
            }
        }
    },

    clear() {
        if (this.alpineComponent && this.alpineComponent.toasts) {
            this.alpineComponent.toasts.forEach(toast => {
                toast.visible = false;
            });
            setTimeout(() => {
                this.alpineComponent.toasts.length = 0;
            }, CONSTANTS.TOAST_FADE_DURATION);
        }
    }
};

const APIUtils = {
    async request(url, options = {}) {
        const defaultOptions = {
            headers: {
                'X-CSRFToken': Utils.getCSRFToken()
            }
        };

        if (options.body && typeof options.body === 'string') {
            defaultOptions.headers['Content-Type'] = 'application/json';
        }

        const mergedOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, mergedOptions);
            
            const contentType = response.headers.get('content-type');
            let data;
            
            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            } else {
                data = await response.text();
            }
            
            if (!response.ok) {
                const errorMessage = typeof data === 'object' && data.message 
                    ? data.message 
                    : `HTTP ${response.status}: ${response.statusText}`;
                throw new Error(errorMessage);
            }

            return { success: true, data };
        } catch (error) {
            const result = Utils.handleError(error, `API ${options.method || 'GET'} ${url}`);
            
            if (ToastManager.alpineComponent) {
                ToastManager.show(result.message, 'error');
            }
            
            return result;
        }
    },

    get(url) {
        return this.request(url, { method: 'GET' });
    },

    post(url, data) {
        if (data instanceof FormData) {
            return this.request(url, {
                method: 'POST',
                body: data
            });
        }
        
        return this.request(url, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    },

    put(url, data) {
        return this.request(url, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    },

    delete(url) {
        return this.request(url, { method: 'DELETE' });
    }
};

const FormUtils = {
    serialize(formElement) {
        const formData = new FormData(formElement);
        const data = {};
        for (const [key, value] of formData.entries()) {
            data[key] = value;
        }
        return data;
    },

    validate(data, rules) {
        const errors = {};
        
        for (const [field, fieldRules] of Object.entries(rules)) {
            const value = data[field];
            
            if (!fieldRules) continue;
            
            if (fieldRules.required && (!value || !value.toString().trim())) {
                errors[field] = fieldRules.requiredMessage || `${field} is required`;
                continue;
            }
            
            if (value || fieldRules.required) {
                if (value && fieldRules.pattern && !fieldRules.pattern.test(value)) {
                    errors[field] = fieldRules.patternMessage || `Invalid ${field} format`;
                }
                
                if (value && fieldRules.min !== undefined) {
                    const length = value.toString().length;
                    if (length < fieldRules.min) {
                        errors[field] = fieldRules.minMessage || `${field} must be at least ${fieldRules.min} characters`;
                    }
                }
                
                if (value && fieldRules.max !== undefined) {
                    const length = value.toString().length;
                    if (length > fieldRules.max) {
                        errors[field] = fieldRules.maxMessage || `${field} must be no more than ${fieldRules.max} characters`;
                    }
                }
                
                if (fieldRules.custom && typeof fieldRules.custom === 'function') {
                    const customError = fieldRules.custom(value, data);
                    if (customError) {
                        errors[field] = customError;
                    }
                }
            }
        }
        
        return {
            isValid: Object.keys(errors).length === 0,
            errors
        };
    }
};

class PollingManager {
    constructor() {
        this.intervals = new Map();
        this.callbacks = new Map();
        this.isActive = true;
    }

    start(key, callback, interval) {
        this.stop(key);
        
        this.callbacks.set(key, { callback, interval });
        
        if (this.isActive) {
            callback();
            
            const intervalId = setInterval(() => {
                if (this.isActive) {
                    callback();
                }
            }, interval);
            
            this.intervals.set(key, intervalId);
        }
    }

    stop(key) {
        const intervalId = this.intervals.get(key);
        if (intervalId) {
            clearInterval(intervalId);
            this.intervals.delete(key);
        }
    }

    stopAll() {
        for (const [key] of this.intervals) {
            this.stop(key);
        }
    }

    pause() {
        this.isActive = false;
    }

    resume() {
        this.isActive = true;
        for (const [key, { callback, interval }] of this.callbacks) {
            this.start(key, callback, interval);
        }
    }

    destroy() {
        this.stopAll();
        this.callbacks.clear();
        this.isActive = false;
    }
}

const ThemeManager = {
    current: 'dark',

    init(theme = 'dark') {
        const saved = localStorage.getItem('lumentrace-theme');
        this.current = saved || theme;
        this.apply();
    },

    apply() {
        if (this.current === 'light') {
            document.body.classList.add('light-theme');
        } else {
            document.body.classList.remove('light-theme');
        }
        
        localStorage.setItem('lumentrace-theme', this.current);
    },

    toggle() {
        this.current = this.current === 'dark' ? 'light' : 'dark';
        this.apply();
        return this.current;
    },

    set(theme) {
        if (['dark', 'light'].includes(theme)) {
            this.current = theme;
            this.apply();
        }
    }
};

if (typeof window !== 'undefined') {
    window.LumenTrace = {
        Utils,
        ToastManager,
        APIUtils,
        FormUtils,
        PollingManager,
        ThemeManager,
        CONSTANTS
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            ThemeManager.init();
        });
    } else {
        ThemeManager.init();
    }
}

window.LumenTrace = {
    Utils,
    ToastManager,
    APIUtils,
    FormUtils,
    PollingManager,
    ThemeManager,
    CONSTANTS
};

APIUtils.discoverMac = function(ip) {
    return this.get(`/discover_mac?ip=${encodeURIComponent(ip)}`);
};

LumenTrace.Debug = {
    async testEndpoints() {
        const endpoints = [
            '/get_ups_status',
            '/get_devices', 
            '/get_logs',
            '/get_battery_analytics',
            '/discover_mac?ip=192.168.1.1'
        ];
        
        console.log('Testing API endpoints...');
        
        for (const endpoint of endpoints) {
            try {
                const response = await fetch(endpoint);
                console.log(`${endpoint}: ${response.status} ${response.statusText}`);
                
                if (response.ok) {
                    const data = await response.json();
                    console.log(`${endpoint} data:`, data);
                } else {
                    console.error(`${endpoint} failed:`, await response.text());
                }
            } catch (error) {
                console.error(`${endpoint} error:`, error);
            }
        }
    },
    

    testCSRF() {
        const token = LumenTrace.Utils.getCSRFToken();
        console.log('CSRF Token:', token || 'NOT FOUND');
        
        const metaTag = document.querySelector('meta[name="csrf-token"]');
        console.log('CSRF Meta Tag:', metaTag ? metaTag.outerHTML : 'NOT FOUND');
    },
    

    async testAPICall() {
        console.log('Testing API call...');
        const result = await LumenTrace.APIUtils.get('/get_devices');
        console.log('API Result:', result);
    },

    checkFunctions() {
        const requiredFunctions = [
            'LumenTrace.Utils.getCSRFToken',
            'LumenTrace.Utils.validateIP',
            'LumenTrace.Utils.validateMAC',
            'LumenTrace.Utils.normalizeMac',
            'LumenTrace.Utils.sanitizeInput',
            'LumenTrace.Utils.debounce',
            'LumenTrace.APIUtils.get',
            'LumenTrace.APIUtils.post',
            'LumenTrace.ToastManager.show'
        ];

        console.log('Checking required functions:');
        requiredFunctions.forEach(funcPath => {
            const exists = funcPath.split('.').reduce((obj, prop) => obj && obj[prop], window);
            console.log(`${funcPath}: ${exists ? '✓ EXISTS' : '✗ MISSING'}`);
        });
    }
};