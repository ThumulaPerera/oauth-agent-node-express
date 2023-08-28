import { config } from '../appConfig'; 
import AppConfiguration from './appConfiguration';

class ConfigManager {
    get config(): AppConfiguration {
      return config
    }
}

export default new ConfigManager();
