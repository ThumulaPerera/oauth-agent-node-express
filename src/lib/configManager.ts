import { config } from '../config'; 
import OAuthAgentConfiguration from './oauthAgentConfiguration';

class ConfigManager {
    get config(): OAuthAgentConfiguration {
      return config
    }
}

export default new ConfigManager();
