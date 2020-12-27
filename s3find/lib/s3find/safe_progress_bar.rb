require 'ruby-progressbar'

class SafeProgressBar < ProgressBar::Base
    
    def progress=(new_progress)
      self.total = new_progress if total <= new_progress
      super
    end

    def total=(new_total)
      super if new_total && new_total > 0
    end
end